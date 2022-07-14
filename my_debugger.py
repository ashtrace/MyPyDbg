from cgitb import handler
from concurrent.futures import thread
from ctypes import *
from ctypes.wintypes import HMODULE, LPCVOID
from itertools import count
from operator import length_hint
from pickle import READONLY_BUFFER
from sys import orig_argv
from time import sleep
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        self.debugger_active        = False
        self.first_breakpoint       = True
        self.h_process              = None
        self.pid                    = None
        self.h_thread               = None
        self.context                = None
        self.exception              = None
        self.exception_address      = None
        self.software_breakpoints   = {}
        self.hardware_breakpoints   = {}

#############################################################################
#                                                                           #
#                            PROCESS HANDLING                               #
#                                                                           #
#############################################################################

    # FUNCTION: open_process
    # INPUT:
    #   pid : Process ID of debugee
    # PROCESS:
    #   open handle to process with PROCESS_ALL_ACCESS
    # OUTPUT:
    #   h_process : process handle
    def open_process(self, pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if h_process:
            return h_process

    # FUNCTION: attach
    # INPUT:
    #   pid : Process ID of debugee
    # PROCESS:
    #   attach to debugee process
    # OUTPUT: None    
    def attach(self, pid):
        self.h_process = self.open_process(pid)

        # We attempt to attch to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active    = True
            self.pid                = int(pid)
        else:
            print("[*] Unable to attach to the process")

    # FUNCTION: detach
    # INPUT: None
    # PROCESS:
    #   detach from debugee process
    # OUTPUT: None  
    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting...")
            return True
        else:
            print("[*] There was an error")
            return False

#############################################################################
#                                                                           #
#                            EXECUTABLE LOADER                              #
#                                                                           #
#############################################################################

    # FUNCTION: load
    # INPUT:
    #   path_to_exe : filesystem path to executable file to be loaded
    # PROCESS:
    #   a) create process
    #   b) obtain process handle
    # OUTPUT: None
    def load(self, path_to_exe):
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want
        # to see the calculator GUI
        creation_flags = DEBUG_PROCESS

        # instantiate the structs
        startupinfo         = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        # The following two options allow the started process
        # to be shown as a separate window. This also
        # illustrates how different settings in the
        # STARTUPINFO struct can affect the debuggee.
        startupinfo.dwFlags     = 0x1
        startupinfo.wShowWindow = 0x0

        # We then initialize the cb variable in the STARTUPINFO
        # struct which is just the size of struct itself
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(path_to_exe,
                                    None,
                                    None,
                                    None,
                                    None,
                                    creation_flags,
                                    None,
                                    None,
                                    byref(startupinfo),
                                    byref(process_information)):
            print("[*] We have successfully launched the process!")
            print(f"[*] PID: {process_information.dwProcessId}")

            # Obtain a valid handle to the newly created process
            # and store it for future access
            self.h_process = self.open_process(process_information.dwProcessId)

        else:
            print(f"[*] Error: {kernel32.GetLastError()}")

#############################################################################
#                                                                           #
#                            THREAD HANDLING                                #
#                                                                           #
#############################################################################

    # FUNCTION: open_thread
    # INPUT:
    #   thread_id : ID of thread to open
    # PROCESS:
    #   open handle to thread with THREAD_ALL_ACCESS
    # OUTPUT:
    #   h_thread : thread handle
    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if h_thread is not None:
            return h_thread
        else:
            return False

    # FUNCTION: enumerate_threads
    # INPUT: None
    # PROCESS:
    #   a) retrieve debugee process snapshot
    #   b) for each thread in snapshot filter threads owned by debugee process
    # OUTPUT:
    #   thread_list : list of all threads of debugee process
    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot is not None:
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)

                success = kernel32.Thread32Next(snapshot, byref(thread_entry))
            
            kernel32.CloseHandle(snapshot)
            
            return thread_list

        else:
            return False

    # FUNCTION: get_thread_context
    # INPUT: thread_id
    # PROCESS:
    #   retrieve thread's context
    # OUTPUT:
    #   context : thread context
    def get_thread_context(self, thread_id):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        h_thread = self.open_thread(thread_id)
        
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        
        else:
            return False

#############################################################################
#                                                                           #
#                            DEBUG EVENT HANDLER                            #
#                                                                           #
#############################################################################

    # FUNCTION: run
    # INPUT: None
    # PROCESS:
    #   get debug event of debugee if debugger is active
    # OUTPUT: None
    def run(self):
        # Now we have to poll the debuggee for
        # debugging events
        while self.debugger_active == True:
            self.get_debug_event()
        
        return

    # FUNCTION: get_debug_event
    # INPUT: None
    # PROCESS:
    #   a) wait for debug event
    #   b) obtain thread handle of debug event
    #   c) obtain context of thread
    #   d) filter exception events from all debug events
    #   e) filter breakpoints from exceptions
    #   f) continue debug event
    # OUTPUT: None
    def get_debug_event(self):
        debug_event     = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), 100):
            # Let's obtain the thread and context information
            self.h_thread   = self.open_thread(debug_event.dwThreadId)
            self.context    = self.get_thread_context(debug_event.dwThreadId)

            print(f"Thread ID: {debug_event.dwThreadId}, Event Code: {debug_event.dwDebugEventCode}")

            # If the event code is an exception, we want to examine it further
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                # Obtain the exception code
                exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if exception == EXCEPTION_ACCESS_VIOLATION:
                    print("Access Violation Detected")
                
                # If a breakpoint is detected, we call an internal handler
                elif exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                
                elif exception == EXCEPTION_GUARD_PAGE:
                    print("Guard Page Access Detected.")

                elif exception == EXCEPTION_SINGLE_STEP:
                    print("Single Stepping.")

            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

    # FUNCTION: exception_handler_breakpoint
    # INPUT: None
    # PROCESS:
    #   a) print register contents
    #   b) remove breakpoint and resume process
    # OUTPUT: debug event continue status
    def exception_handler_breakpoint(self):
        print("[*] Inside the breakpoint handler.")
        
        print(f"Exception Address: {hex(self.exception_address)}")
        
        print("REGISTER VALUES:")
        print(f"RAX: {hex(self.context.Rax)}")
        print(f"RBX: {hex(self.context.Rbx)}")
        print(f"RCX: {hex(self.context.Rcx)}")
        print(f"RDX: {hex(self.context.Rdx)}")
        print(f"RSI: {hex(self.context.Rsi)}")
        print(f"RDI: {hex(self.context.Rdi)}")
        print(f"RBP: {hex(self.context.Rbp)}")
        print(f"RSP: {hex(self.context.Rsp)}")
        print(f"RIP: {hex(self.context.Rip)}")
        
        if self.exception_address in self.software_breakpoints:
            print(f"[*] Hit user defined breakpoint.")
            sleep(10)
            # remove breakpoint (restore original instruction), and resume
            self.write_process_memory(self.exception_address, self.software_breakpoints[self.exception_address][1])
            print(f"[DEBUG > exception_handler_breakpoint] Wrote byte: {self.read_process_memory(self.exception_address, 1)} at {hex(self.exception_address)}")
            self.software_breakpoints.pop(self.exception_address)            
            return DBG_EXCEPTION_NOT_HANDLED

        return DBG_CONTINUE

#############################################################################
#                                                                           #
#                            SOFTWARE BREAKPOINTS                           #
#                                                                           #
#############################################################################

    # FUNCTION: read_process_memory
    # INPUT:
    #   address : memory address to read from
    #   length : size of block to read
    # PROCESS:
    #   read specified address block from process memory 
    # OUTPUT:
    #   data : memory data read
    def read_process_memory(self, address, length):
        data        = b''
        read_buf    = create_string_buffer(length)
        count       = c_ulong(0)

        # Setting argtype (argument type) and restype (return type) of ReadProcessMemory, else it returns ERROR_INVALID_HANDLE
        _ReadProcessMemory          = kernel32.ReadProcessMemory
        _ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
        _ReadProcessMemory.restype  = BOOL

        if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
            return False
        else:
            data += read_buf.raw
            return data

    # FUNCTION: write_process_memory
    # INPUT:
    #   address : memory address to write to
    #   length : size of block to write
    # PROCESS:
    #   write to specified address block in process memory 
    # OUTPUT: success status
    def write_process_memory(self, address, data):
        count   = c_ulong(0)
        length  = len(data)

        c_data = c_char_p(data[count.value:])

        # Setting argtype (argument type) and restype (return type) of WriteProcessMemory, else it returns ERROR_INVALID_HANDLE
        _WriteProcessMemory = kernel32.WriteProcessMemory
        _WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, SIZE_T, POINTER(SIZE_T)]
        _WriteProcessMemory.restype = BOOL

        if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
            return False
        else:
            return True

    # FUNCTION: bp_set_sw
    # INPUT:
    #   address : memory address to set breakpoint at
    # PROCESS:
    #   a) read the byte stored at "address"
    #   b) store the byte read
    #   c) write interrupt opcode '\xCC' (int3) at "address" 
    # OUTPUT: success status
    def bp_set_sw(self, address):
        if address not in self.software_breakpoints:
            try:
                # store the orignal byte
                original_byte = self.read_process_memory(address, 1)
                print(f"[DEBUG > bp_set_sw] original_byte: {original_byte}")
                # write the INT3 opcode
                self.write_process_memory(address, b'\xCC')
                # register the breakpoint in our internal list
                self.software_breakpoints[address] = (address, original_byte)

            except:
                print(f"[DEBUG > bp_set_sw] Failed set breakpoint at: {hex(address)}")
                print(f"[DEBUG] for read_process_memory in bp_set_sw. Error code: {kernel32.GetLastError()}")

                return False
            
            return True

    # FUNCTION: func_resolve
    # INPUT:
    #   dll : the dynamic link library storing the function
    #   function : the function symbol to be resolved
    # PROCESS:
    #   a) obtain handle for dll
    #   b) resolve function symbol address in dll
    # OUTPUT: address of resolved function in dll
    def func_resolve(self, dll, function):
        # Setting argtype (argument type) and restype (return type) of WriteProcessMemory, else GetModuleHandle fails with no such module (ERROR_MOD_NOT_FOUND)
        _GetModuleHandleA           = kernel32.GetModuleHandleA
        _GetModuleHandleA.argtypes  = [LPCSTR]
        _GetModuleHandleA.restype   = POINTER(c_void_p)
        
        handle      = kernel32.GetModuleHandleA(dll.encode('ascii'))
        
        if handle:
            # Setting argtype (argument type) and restype (return type) of WriteProcessMemory, else GetProcAddress fails with no such procedure (ERROR_PROC_NOT_FOUND)
            _GetProcAddress             = kernel32.GetProcAddress
            _GetProcAddress.argtypes    = [HMODULE, LPCSTR]
            _GetProcAddress.restype     = c_void_p

            address     = kernel32.GetProcAddress(handle, function.encode('ascii'))
            if address:
                kernel32.CloseHandle(handle)
                return address

            else:
                print(f"[DEBUG > func_resolve] failed to retrieve address of {function}. Error code: {kernel32.GetLastError()}")            
        else:
            print(f"[DEUBG > func_resolve] Failed to obtain handle for {dll}. Error code: {kernel32.GetLastError()}")