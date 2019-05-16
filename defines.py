from ctypes import *

# Let's map the Microsoft types to ctypes for clarity
BYTE = c_ubyte
WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char) 
HANDLE = c_void_p
PVOID = c_void_p
LPVOID = c_void_p
UINT_PTR = c_ulong
SIZE_T = c_ulong

# Constants
DEBUG_PROCESS = 0x00000001
PROCESS_ALL_ACCESS = 0x001F0FFF
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
DBG_NOT_HANDLE = 0x80010001


# Debug event constants
EXCEPTION_DEBUG_EVENT = 0x00000001
CREATE_THREAD_DEBUG_EVENT = 0x00000002
CREATE_PROCESS_DEBUG_EVENT = 0x00000003
EXIT_THREAD_DEBUG_EVENT = 0x00000004
EXIT_PROCESS_DEBUG_EVENT = 0x00000005
LOAD_DLL_DEBUG_EVENT = 0x00000006
UNLOAD_DLL_DEBUG_EVENT = 0x00000007
OUTPUT_DEBUG_STRING_EVENT = 0x00000008

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_CRASHED = 0xC0000000
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_SINGLE_STEP = 0x80000004

# Thread constants for CreateToolhelp32Snapshot()
THREAD_ALL_ACCESS = 0x001F03FF

# Context flags for GetThreadContext()
CONTEXT_FULL = 0x00010007
CONTEXT_DEBUG_REGISTERS = 0x00010010

# Memory permissions
PAGE_EXECUTE_READWRITE = 0x00000040

# Format message kernel32 raise
FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000

# Memory page permissions, used by VirtualProtect()
PAGE_NOACCESS = 0x00000001
PAGE_READONLY = 0x00000002
PAGE_READWRITE = 0x00000004
PAGE_WRITECOPY = 0x00000008
PAGE_EXECUTE = 0x00000010
PAGE_EXECUTE_READ = 0x00000020
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_EXECUTE_WRITECOPY = 0x00000080
PAGE_GUARD = 0x00000100
PAGE_NOCACHE = 0x00000200
PAGE_WRITECOMBINE = 0x00000400


# Structures for CreateProcessA() function
# STARTUPINFO describes how to spawn the process
class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", DWORD),        
        ("lpReserved", LPTSTR), 
        ("lpDesktop", LPTSTR),  
        ("lpTitle", LPTSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]

# PROCESS_INFORMATION receives its information
# after the target process has been successfully
# started.
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]

# When the dwDebugEventCode is evaluated
class EXCEPTION_RECORD(Structure):
    pass
    
EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress", PVOID),
        ("NumberParameters", DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
    ]

# Exceptions
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD),
    ]

# it populates this union appropriately
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
    ]   

# DEBUG_EVENT describes a debugging event
# that the debugger has trapped
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]

# Used by the CONTEXT structure
class FLOATING_SAVE_AREA(Structure):
   _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]

# The CONTEXT structure which holds all of the 
# register values after a GetThreadContext() call
class CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
    ]

# Supporting struct for the SYSTEM_INFO_UNION union
class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
    ]


# Supporting union for the SYSTEM_INFO struct
class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dwOemId", DWORD),
        ("sProcStruc", PROC_STRUCT),
    ]

# SYSTEM_INFO structure is populated when a call to 
# kernel32.GetSystemInfo() is made. We use the dwPageSize
# member for size calculations when setting memory breakpoints
class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]

