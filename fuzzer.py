# coding: utf-8

import os
import sys
import framework
import struct
import traceback
import binascii
import io
from xml.etree.ElementTree import parse

VERSION = int(sys.version[0])
if(VERSION > 2):
    import winreg
else:
    import _winreg as winreg


p32 = lambda x: struct.pack("<L", x)
byte = lambda x: struct.pack("<B", x)

class MutateFuzzer(framework.FileFuzzer):
    def __init__(self, target, file_type, interval):
        framework.FileFuzzer.__init__(self, target, file_type, interval)
        self.mutate_functions = {
            self.replace_offset : [byte(0x00), byte(0xff), byte(0x03), byte(0x15), byte(0xaa)]#, p32(0x7fffffff)]
            #,
            #self.append_offset : [byte(0xff), "A"*3000]
        } # Functions should return mutate_mode
        
    def after_run_process(self):
        pass
        #os.system("send_key.vbs")
        
    def set_file_size(self):
        file_name = self.sample_name
        sample_file=open(file_name, "rb+")
        sample_data=sample_file.read()
        sample_file.close()
        file_size=len(sample_data)
        
        self.set_fuzz_iter(file_size) #fuzzer model's loop count
        
    def replace_offset(self, file_name, file_offset, mutate_bytes):
        file=open(file_name, "rb+")
        file.seek(file_offset)
        origin_byte = file.read(len(mutate_bytes))
        if(origin_byte == mutate_bytes):
            flag = -1
        else:
            flag = "REPLACE"
        file.seek(file_offset)
        file.write(mutate_bytes)
        file.close()
        return flag #if returns -1 then pass through without run process for current byte
    
    def append_offset(self, file_name, file_offset, mutate_bytes):
        file=open(file_name, "rb")
        file_data=file.read()
        file.close()
        file_front=file_data[:file_offset]
        file_back=file_data[file_offset:]
        mutated_data=str(file_front)+str(mutate_bytes)+str(file_back)
        mutated_file=open(file_name, "w")
        mutated_file.write(mutated_data)
        mutated_file.close()
        return "APPEND"
        
    def log_write(self, fp, data):
        if(VERSION == 2):
            fp.write(unicode(data))
        else:
            fp.write(str(data))
    
    def log_crash(self, dump_file, dbg, mutate_info):
        print("[+] Exception Access Violation!")
        registers = {}
        registers['eip']="0x%08x"%(dbg.context.Eip)
        registers['esp']="0x%08x"%(dbg.context.Esp)
        registers['ebp']="0x%08x"%(dbg.context.Ebp)
        registers['eax']="0x%08x"%(dbg.context.Eax)
        registers['ebx']="0x%08x"%(dbg.context.Ebx)
        registers['ecx']="0x%08x"%(dbg.context.Ecx)
        registers['edx']="0x%08x"%(dbg.context.Edx)
        registers['esi']="0x%08x"%(dbg.context.Esi)
        registers['edi']="0x%08x"%(dbg.context.Edi)
        
        with io.open(dump_file, "w", encoding='utf-8') as log_file:
            self.log_write(log_file, "Mutated: %s\n" % self.mutate_name)
            self.log_write(log_file, "Mutated Stream: %s\n" % mutate_info["mutate"])
            self.log_write(log_file, "Mutated Mode: %s\n" % mutate_info["mode"])
            self.log_write(log_file, "Registers:\n")
            for register in registers:
                self.log_write(log_file, register+": %s\n"%(registers[register])) #save log dump
            memory = dbg.op_codes #eip
            if(memory == -1):
                code_context = "Can't read memory"
            else:
                code_context = str(binascii.hexlify(memory)) + "\n"
            self.log_write(log_file, "\nCODE CONTEXT: \n")
            self.log_write(log_file, str(code_context))
            self.log_write(log_file, "\n")
            self.log_write(log_file, "LOG: \n")
            self.log_write(log_file, dbg.get_log())
        
    def refresh_explorer(self):
        os.system("taskkill /F /IM explorer.exe")
        os.system("start %SystemRoot%\\explorer.exe")
        
    def every_iterate(self, iterate):
        refresh_term = 100
        if(iterate % refresh_term == iterate -1):
            self.refresh_explorer()
            pass
        os.system("cls") #clear screen
        
        
    
class Gflags():
    def __init__(self, process_name):
        self.REG_PATH = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+process_name

    def set_reg(self, h_key, key, name, value):
        exist_value = self.get_reg(h_key, key, name)
        if(exist_value == None or int(exist_value) != value):
                try:
                    print("[+] New value "+name)
                    winreg.CreateKey(h_key, key)
                    registry_key = winreg.OpenKey(h_key, key, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(registry_key, name, 0, winreg.REG_DWORD, value)
                    winreg.CloseKey(registry_key)
                    return True
                except WindowsError:
                    return False
        return False

    def get_reg(self, h_key, key, name):
        try:
            registry_key = winreg.OpenKey(h_key, key, 0, winreg.KEY_READ)
            value, regtype = winreg.QueryValueEx(registry_key, name)
            winreg.CloseKey(registry_key)
            return value
        except WindowsError:
            return None
            
            
    def del_reg(self, h_key, key, name):
        try:
            registry_key = winreg.OpenKey(h_key, key, 0, winreg.KEY_ALL_ACCESS)
            ret = winreg.DeleteValue(registry_key, name)
            winreg.CloseKey(registry_key)
            return ret
        except WindowsError:
            return None
            
    def delete(self):
        gflag_result = self.del_reg(winreg.HKEY_LOCAL_MACHINE, self.REG_PATH, "GlobalFlag")
        pageheap_result = self.del_reg(winreg.HKEY_LOCAL_MACHINE, self.REG_PATH, "PageHeapFlags")
            
    def set(self):
        gflag_result = self.set_reg(winreg.HKEY_LOCAL_MACHINE, self.REG_PATH, "GlobalFlag", 0x02000000)
        pageheap_result = self.set_reg(winreg.HKEY_LOCAL_MACHINE, self.REG_PATH, "PageHeapFlags", 0x3)
        if(gflag_result and pageheap_result):
            print("[+] Set PageHeapFlags = 0x02000000 & PageHeapFlags = 0x3")
            return True
        else:
            print("[+] GlobalFlag and PageHeapFlags Error")
            return False
            

def tag_to_int(tag, text):
    if(tag == None):
        data = 0
    else:
        data = tag.text #ex.) 0x800 or 2048
        if(data.isdigit()):
            data = int(data)
        else:
            try:
                data = int(data, 16)
            except:
                print(text)
                sys.exit()
    return data
    
    
if __name__ == '__main__':
    dashboard_string = ""

    current_path=os.getcwd() #Current directory where python code was started
    try:
        xml_file=sys.argv[1] #Fuzzing target info XML file
    except:
        arg0 = sys.argv[0]
        print("Usage: "+arg0+" [XMLFILENAME]")
        print("ex.) "+arg0+" Hwp.exe.xml")
        sys.exit()
        
    tree = parse(xml_file)
    root = tree.getroot()
    target_full_path = root.find("target").text
    arbitrary_offset = tag_to_int(root.find("offset"), "[+] Arbitrary Offset is not decimal or hexadecimal (TAG <offset></offset>)")
    file_type = root.find("filetype").text
    interval = str(tag_to_int(root.find("interval"), "[+] Interval is not decimal or hexadecimal (TAG <interval></interval>)"))
    gflag_element = tag_to_int(root.find("gflag"), "[+] Gflag and PageHeapFlag is not decimal or hexadecimal (TAG <gflag></gflag>)")

    target_program=target_full_path.split("\\")[-1] #Target program name for fuzzing
    gflag = Gflags(target_program)
    if(gflag_element):
        gflag.set()
        dashboard_string += "[+] Try Gflag = 0x02000000 and PageHeap = 0x3...\r\n"
    else:
        gflag.delete()
        dashboard_string += "[+] Try remove Gflag and PageHeap...\r\n"
    dashboard_string += "[+] Fuzzing in: %s\r\n"% target_program #ex.) Fuzzing in: Hwp.exe
    dashboard_string += "[+] Current directory is: %s\r\n"% current_path #ex.) Current directory is: c:\fuzz
    try:
        fuzzer=MutateFuzzer(target_full_path, file_type, interval)
        fuzzer.set_file_size()
        fuzzer.set_arbitrary_offset(arbitrary_offset)
        fuzzer.init_set() #setting mutater environ
        fuzzer.start(dashboard_string)
    except KeyboardInterrupt:
        os.system("taskkill /F /PID %d"%(os.getpid()))
    except Exception:
        print("[-] Python Exception Occur! PLZ check error.log")
        exc_type, exc_value, exc_traceback = sys.exc_info()
        error_traceback = traceback.format_exception(exc_type, exc_value, exc_traceback)
        #print(error_traceback)
        with open("error.log","w") as f:
            for line in error_traceback:
                f.write(line)
                print(line)