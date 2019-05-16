#coding: utf-8
from ctypes import *
from defines import *
import sys
import struct
import time
import json
import os
import binascii

if(sizeof(c_voidp)==8):
    cpu_bit = 64
else:
    cpu_bit = 32
kernel32 = windll.kernel32

class Debugger():
    def __init__(self):
        self.h_process = None
        self.h_pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context = None
        #self.flag = 0
        
        # Here let's determine and store 
        # the default page size for the system
        # determine the system page size.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        
        self.python_version=int((sys.version)[0])
        self.except_access_violation = False
        
        self.logs = [] # Contains debugger's output
        
        self.op_codes = b""
        
    def debug_set_process_kill_on_exit (self, kill_on_exit):
        if not kernel32.DebugSetProcessKillOnExit(kill_on_exit):
            self.append_log("DebugActiveProcess(%s)" % kill_on_exit)
            
    def append_log(self, string):
        self.logs.append(string)
        
    def get_log(self):
        return "\n".join(self.logs)
            
    def load(self, path_to_exe, command_line):
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want
        # to see the calculator GUI
        creation_flags = DEBUG_PROCESS
    
        # instantiate the structs
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        
        # The following two options allow the started process
        # to be shown as a separate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect
        # the debuggee.
        #startupinfo.dwFlags = 0x1
        #fixed
        #startupinfo.wShowWindow = 0x1
        #2:minimize 1:show 0:noshow
        
        # We then initialize the cb variable in the STARTUPINFO struct
        # which is just the size of the struct itself
        startupinfo.cb = sizeof(startupinfo)
        
        command_line = "\"" + path_to_exe + "\"" + " " + command_line
        path_to_exe = 0 #if not zero then can't find file path
        self.append_log(command_line)
        
        if(self.python_version <= 2): #if python version upper then 3, use CreateProcessW because of unicode
            CreateProcess=kernel32.CreateProcessA
        else:
            CreateProcess=kernel32.CreateProcessW
        
        success = CreateProcess(
            path_to_exe,
            command_line,
            None,
            None,
            None,
            creation_flags,
            None,
            None,
            byref(startupinfo),
            byref(process_information)
        )
        try:
            self.debug_set_process_kill_on_exit(False)
        except:
            pass
            
        if ( success ):
            self.append_log("We have successfully launched the process!")
            self.h_pid = process_information.dwProcessId
            self.append_log("The Process ID I have is: %d" % self.h_pid)
            #self.h_process = process_information.hProcess
            self.h_process = self.open_process(process_information.dwProcessId)
            self.debugger_active = True
            self.close_handle(process_information.hThread)
        else:
            self.append_log("Error with error code %d." % kernel32.GetLastError())
            if(kernel32.GetLastError()==2):
                self.append_log("Can't find file")
            if(kernel32.GetLastError()==3):
                self.append_log("Can't find file")
                


    ####################################################################################################################
    def terminate_process (self, exit_code=0):
        kernel32.TerminateProcess(self.h_process, exit_code)
                
    def open_process(self, pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS , False,pid) #for msdn reference, pid is last argument
        return h_process
        
    def get_thread_context (self, thread_id=None,h_thread=None):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        # Obtain a handle to the thread
        if(h_thread is None):
            self.h_thread = self.open_thread(thread_id)
        if(cpu_bit == 64):
            GetThreadContext = kernel32.Wow64GetThreadContext
        else:
            GetThreadContext = kernel32.GetThreadContext
        if(GetThreadContext(self.h_thread, byref(context))):
            return context 
        else:
            return False

    def little_endian(self, dword_data):
        return struct.pack("<L", dword_data)
        
    def run(self):
        # Now we have to poll the debuggee for
        # debugging events
        while(self.debugger_active == True):
            self.get_debug_event()
            
    def virtual_protect (self, base_address, size, protection):
        old_protect = c_ulong(0)
        if not kernel32.VirtualProtectEx(self.h_process, base_address, size, protection, byref(old_protect)):
            self.append_log("VirtualProtectEx(0x%08x, %d, %08x)" % (base_address, size, protection))
            return -1
        return old_protect.value

    
    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        #continue_status = DBG_CONTINUE
        continue_status = DBG_NOT_HANDLE
        
        if(kernel32.WaitForDebugEvent(byref(debug_event), 100)):
        #if(kernel32.WaitForDebugEvent(byref(debug_event), INFINITE)):
            # grab various information with regards to the current exception.
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(h_thread=self.h_thread)
            self.debug_event = debug_event
            
            #self.append_log("Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode,debug_event.dwThreadId))
            #try:
            #    self.append_log("EIP: 0x%08x"%self.context.Eip)
            #except:
            #    pass
            #memory = self.read_process_memory(self.context.Eip, 20)
            #if(memory == -1):
            #    memory = "Can't read memory"
            
            if(debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT):
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                self.firstchance=debug_event.u.Exception.dwFirstChance
                
                self.op_codes = self.read_process_memory(self.context.Eip, 20)
                # get opcodes before event detect and process terminate
                
                # call the internal handler for the exception event that just occured.
                if( (self.exception ^ EXCEPTION_CRASHED)>>24 == 0 and not self.firstchance): #contains 0xc0000409 , 0xc0000005 ...
                    #sometimes vulnerability defense solution (ex. GS) raise exception not 0xc0000005 but something like 0xc0000409
                    self.append_log("Exception: 0x%x"%self.exception)
                    self.append_log("Access Violation Detected.")
                    self.append_log("EIP: 0x%08x"%self.context.Eip)
                    self.except_access_violation = True
                elif(self.exception == EXCEPTION_BREAKPOINT):
                    self.append_log("EXCEPTION_BREAKPOINT Detected.")
                elif(self.exception == EXCEPTION_GUARD_PAGE):
                    self.append_log("EXCEPTION_GUARD_PAGE Detected.")
                elif(self.exception == EXCEPTION_SINGLE_STEP):
                    self.append_log("EXCEPTION_SINGLE_STEP Detected.")
            elif(debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT):
                self.debugger_active = False
            self.close_handle(self.h_thread)
            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

    def close_handle (self, handle):
        return kernel32.CloseHandle(handle)
        
    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if(h_thread != None):
            return h_thread
        else:
            self.append_log("Could not obtain a valid thread handle.")
            return False
            
    def read_process_memory (self, address, length):
        data         = b""
        read_buf     = create_string_buffer(length)
        count        = c_ulong(0)
        orig_length  = length
        orig_address = address

        # ensure we can read from the requested memory space.
        _address = address
        _length  = length

        try:
            old_protect = self.virtual_protect(_address, _length, PAGE_EXECUTE_READWRITE)
        except:
            pass

        while length:
            if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
                if not len(data):
                    self.append_log("ReadProcessMemory(%08x, %d, read=%d)" % (address, length, count.value))
                    return -1
                else:
                    return data

            data    += read_buf.raw
            length  -= count.value
            address += count.value

        # restore the original page permissions on the target memory region.
        try:
            self.virtual_protect(_address, _length, old_protect)
        except:
            pass

        return data