# coding: utf-8

import debugger
#from defines import *
import defines
from threading import Thread
import logo
import os
import sys
import fnmatch #wildcard
import shutil
import time

class FileFuzzer():
    def __init__(self, target, file_type, interval):
        self.target = target # c:\windows\hwp.exe
        self.interval = interval
        
        self.file_type = file_type
        
        self.current_path = os.getcwd() # c:\users\user\fuzzer\
        self.target_program = target.split("\\")[-1] # hwp.exe
        self.mutate_path = "%s\\%s_%s_mutated\\" % (self.current_path, self.target_program, self.file_type) # ex.) C:/fuzz/Hwp.exe_hwp_mutated/
        self.crash_path = "%s\\%s_%s_crashed\\" % (self.current_path, self.target_program, self.file_type) # ex.) C:/fuzz/Hwp.exe_hwp_crashed/
        self.sample_path = "%s\\samplefiles\\" % (self.current_path)
        
        self.file_name = "test"
        self.sample_name = "%s\\%s.%s"%(self.sample_path, self.file_name, self.file_type) #c:/fuzz/samplefiles/test.hwp
        
        self.arbitrary_offset = 0 # For continue last mutated file
        self.fuzz_iter = None
        
        self.mutate_name = None
        self.version=int(sys.version[0])
        
        self.mutate_functions = {}
        self.mode_iter = 0 #index of mutate mode (mutate_function's index)
        self.change_index = 0 #index of mutate stream (mutate function's value index)
        self.iterate = 0
        
    def set_arbitrary_offset(self, offset=0):
        self.arbitrary_offset = offset
        
    def escape(self, str):
        if(self.version == 2):
            return str.encode("string-escape")
        else:
            return repr(str)
        
    def compress_str(self, string):
        if(len(string)>16):
            compressed=self.escape(string[:16])+"...+("+str(len(string))+")"
        else:
            compressed=self.escape(string)
        return compressed
        
    def mutate_file(self, mutate_file, offset):
        self.mode_count = len(self.mutate_functions) #maximum size for mode iteration
        if(self.mode_count == 0): #if user not defined mutate functions
            sys.exit("[+] You did not defined mutate functions")
        return_dict = {"mode":None, "mutate":None, "step":None, "index":None}
        
        function = list(self.mutate_functions.keys())[self.mode_iter]
        mutate_list = self.mutate_functions[function]
        change_stream = mutate_list[self.change_index]
        
        mode = function(mutate_file, offset, change_stream)
        if(self.change_index >= len(mutate_list)-1): #mode change if index is higher than list size
            self.mode_iter += 1
            self.change_index = 0
        else: #if index is lower than list size
            self.change_index += 1
        offset_add = 0
        #print(self.mode_iter)
        #print(self.mode_count)
        #print(self.change_index)
        if(self.mode_iter >= self.mode_count): #if all mode finished then move to next offset and start with first mode
            self.mode_iter = 0
            offset_add = 1
        return_dict["mode"] = mode #if mutate function returns -1 then pass through
        return_dict["mutate"] = self.compress_str(change_stream)
        return_dict["step"] = offset_add
        return_dict["index"] = self.change_index
        
        return return_dict
        
    def log_crash(self, dump_file, dbg, mutate_info):
        ############################
        #Override user should define
        ############################
        pass
        
    def after_run_process(self):
        ############################
        #Override user should define
        ############################
        pass
        
    def every_iterate(self, iterate):
        ############################
        #Override user should define
        ############################
        pass
        
    def set_fuzz_iter(self, times):
        self.fuzz_iter = times
        
    def flush_mutate_dir(self):
        try: #for check fuzzed offset
            last_offset=open(self.mutate_path+"MUTATEOFFSET.txt", "r")
            self.arbitrary_offset=int(last_offset.read())
            last_offset.close()
        except:
            pass
            
        try: #for remove all in mutate_path except MUTATEOFFSET.txt
            mutate_path_list=os.listdir(self.mutate_path)
            mutate_path_list.remove("MUTATEOFFSET.txt")
        except:
            pass
        for file_name in mutate_path_list: #remove except OFFSET file
            os.remove(self.mutate_path+file_name)
            
    def save_checkpoint(self, offset):
        last_offset=open(self.mutate_path+"MUTATEOFFSET.txt", "w") #make checkpoint
        last_offset.write(str(offset))
        last_offset.close()
        
    def init_set(self):
        if(os.path.isdir(self.mutate_path) == 0): # If mutate directory not exists create directory
            os.mkdir(self.mutate_path)
        if(os.path.isdir(self.crash_path) == 0): # If crash directory not exists create directory
            os.mkdir(self.crash_path)
        self.flush_mutate_dir()
    
    def dash_board(self, dashboard):
        try:
            crashes=os.listdir(self.crash_path)
        except:
            crashes=[]
        crash_count=fnmatch.filter(crashes, "*.txt")
        print("=============================================================")
        print(dashboard)
        print("                     Loop times: "+str(self.iterate))
        print("                     Total Crash: "+str(len(crash_count)))
        print("                     Set Interval: "+self.interval)
        print("=============================================================\n")
        
    def start_dbg(self, program, args):
        self.dbg = debugger.Debugger()
        self.dbg.load(program, args)
        self.dbg.run()
        
    def start(self, dashboard):
        offset = self.arbitrary_offset
        iterate = 0
        while(1):
            self.iterate += 1
            self.every_iterate(iterate)
            if(offset >= self.fuzz_iter):
                print("%d >= %d"%(offset,self.fuzz_iter))
                break
            logo.print_logo_fire()
            self.dash_board(dashboard)
            self.mutate_name = "%s\\mutated_0x%x.%s" % (self.mutate_path, offset, self.file_type) #./hwp.exe_hwp_mutated/mutated_0x5f.hwp
            shutil.copy(self.sample_name, self.mutate_name)
            mutate_info = self.mutate_file(self.mutate_name, offset)
            
            mutate_step = 0
            
            mutate_mode = mutate_info["mode"]
            mutate_stream = mutate_info["mutate"]
            mutate_step = mutate_info["step"]
            mutate_index = mutate_info["index"]
            if(mutate_mode == -1):
                print("[-] Not Run Process ( Passed )")
                print("[+] Now Processing : %s" % self.mutate_name)
                print("[+] Mutated Offset: 0x%x" % int(offset))
            else:
                iterate += 1 #for counting loop times
                print("[+] Now Processing : %s" % self.mutate_name)
                print("[+] Mutated Mode: %s" % mutate_mode)
                print("[+] Mutated Offset: 0x%x" % int(offset))
                print("[+] Mutated Bytes: %s" % mutate_stream)
                
                dump_file_name = "%s\\DUMP_0x%x_0x%x_%s.txt" % (self.crash_path, offset, mutate_index, mutate_mode)
                
                dbg_thread = Thread(target=self.start_dbg, args=(self.target, "\""+self.mutate_name+"\"", ))
                dbg_thread.start()
                
                time.sleep(float(self.interval))
                
                self.after_run_process()
                
                if(self.dbg.except_access_violation):
                    self.log_crash(dump_file_name, self.dbg, mutate_info)
                self.dbg.terminate_process()
                self.dbg.close_handle(self.dbg.h_process)
                
                dbg_thread.join() #join thread
            offset += int(mutate_step)
            while(1):
                try:
                    os.remove(self.mutate_name)
                    break
                except WindowsError:
                    time.sleep(0.1)
            self.save_checkpoint(offset)
        print("[+] Fuzzing finished")
        logo.print_logo_fire()
        self.dash_board(dashboard)
