from ctypes.wintypes import HMODULE, LPCVOID
from time import sleep

from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():

#############################################################################
#                                                                           #
#                               INITIALIZATION                              #
#                                                                           #
#############################################################################

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
        self.guarded_pages          = []
        self.memory_breakpoints     = {}

        # Determine the default page size
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

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
#                            DEBUGEE MEMORY ACCESS                          #
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

#############################################################################
#                                                                           #
#                            VALUE/ADDRESS RESOLUTION                       #
#                                                                           #
#############################################################################

    # FUNCTION: func_resolve
    # INPUT:
    #   dll : the dynamic link library storing the function
    #   function : the function symbol to be resolved
    # PROCESS:
    #   a) obtain handle for dll
    #   b) resolve function symbol address in dll
    # OUTPUT: address of resolved function in dll
    def func_resolve(self, dll, function):
        # Setting argtype (argument type) and restype (return type) of WriteProcessMemory
        # Else GetModuleHandle fails with no such module (ERROR_MOD_NOT_FOUND)
        _GetModuleHandleA           = kernel32.GetModuleHandleA
        _GetModuleHandleA.argtypes  = [LPCSTR]
        _GetModuleHandleA.restype   = POINTER(c_void_p)
        
        handle      = kernel32.GetModuleHandleA(dll.encode('ascii'))
        
        if handle:
            # Setting argtype (argument type) and restype (return type) of WriteProcessMemory
            # Else GetProcAddress fails with no such procedure (ERROR_PROC_NOT_FOUND)
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


    # FUNCTION: reg_resolve
    # INPUT: None
    # PROCESS:
    #   a) print value of common general purpose registers as well as special purpose registers
    # OUTPUT: None
    def reg_resolve(self):
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

#############################################################################
#                                                                           #
#                            DEBUG EVENT HANDLING                           #
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
    #   f) handle the breakpoint
    #   g) continue debug event
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
                
                elif exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                
                elif exception == EXCEPTION_GUARD_PAGE:
                    self.exception_handler_guard_pages()

                elif exception == EXCEPTION_SINGLE_STEP:
                    continue_status = self.exception_handler_single_step()

            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

#############################################################################
#                                                                           #
#                            BREAKPOINT HANDLERS                            #
#                                                                           #
#############################################################################

    # FUNCTION: exception_handler_breakpoint
    # INPUT: None
    # PROCESS:
    #   a) print register contents
    #   b) remove breakpoint and resume process
    # OUTPUT: debug event continue status
    def exception_handler_breakpoint(self):        
        continue_status = DBG_CONTINUE

        if self.exception_address in self.software_breakpoints:
            print(f"[DEBUG > exeception_handler_breakpoint] Hit user defined software breakpoint.")
            
            # print register values
            self.reg_resolve()

            # sleep to demonstrate that process is hung at breakpoint
            sleep(10)
            
            # remove breakpoint
            self.bp_del_sw()
            print("[DEBUG > exeception_handler_breakpoint] Software breakpoint removed.")

            # When the breakpoint is first encountered, we inform debugee process of
            # the exception and ask it to handle the same (DBG_EXCEPTION_NOT_HANDLED), as debugee fails to do so
            # we get back the exception back and this time we inform it that the exception
            # has been handled (DBG_CONTINUE), this eliminates 'Access Violation' exceptions
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        return continue_status

    # FUNCTION: exception_handler_single_step
    # INPUT: None
    # PROCESS:
    #   a) determine if INT1 was indeed caused by our hardware breakpoint
    #       a1) print register contents
    #       a2) remove breakpoint and resume process
    # OUTPUT: debug event continue status
    def exception_handler_single_step(self):
        slot = None

        # Determine if the single step event was cause by hardware breakpoint set by us
        if self.context.Dr6 & 0x1 and 0 in self.hardware_breakpoints:
            slot = 0
        elif self.context.Dr6 & 0x2 and 1 in self.hardware_breakpoints:
            slot = 1
        elif self.context.Dr6 & 0x4 and 2 in self.hardware_breakpoints:
            slot = 2
        elif self.context.Dr6 & 0x8 and 3 in self.hardware_breakpoints:
            slot = 3
        else:
            # It wasn't generated by a hardware breakpoint
            continue_status = DBG_EXCEPTION_NOT_HANDLED
        
        if slot is not None:
            print(f"[DEBUG > exeception_handler_single_step] Hit user defined hardware breakpoint.")
            # print register contents
            self.reg_resolve()
            # sleep to demonstrate that process is hung at breakpoint
            sleep(10)
            
        # Remove the breakpoint from the list
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE

        print("[DEBUG > exeception_handler_single_step] Hardware breakpoint removed.")
        
        return continue_status

    # FUNCTION: exception_handler_guard_pages
    # INPUT: None
    # PROCESS:
    #   a) determine if guard page exception was caused by us 
    #       a1) print register contents
    #       a2) remove breakpoint and resume process
    # OUTPUT: success status
    def exception_handler_guard_pages(self):
        # We rely on OS's internal mechanism to restore page permissions,
        # and thus do not change continue_status for ContinueDebugEvent()

        # Validate the cause of guard page exception was indeed one of the breakpoints
        if self.exception_address in self.memory_breakpoints:
            print(f"[DEBUG > exeception_handler_guard_pages] Hit user defined memory breakpoint.")

            # print register contents
            self.reg_resolve()
            # sleep to demonstrate that process is hung at breakpoint
            sleep(10)

            # remove breakpoint information from internal data structures
            self.bp_del_mem(self.exception_address)

            print("[DEBUG > exeception_handler_guard_pages] Memory breakpoint removed.")

            return True

        return False


#############################################################################
#                                                                           #
#                            SOFTWARE BREAKPOINTS                           #
#                                                                           #
#############################################################################

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
                # write the INT3 opcode
                self.write_process_memory(address, b'\xCC')
                # register the breakpoint in our internal list
                self.software_breakpoints[address] = (address, original_byte)

            except:
                print(f"[DEBUG > bp_set_sw] Failed set breakpoint at: {hex(address)}")
                print(f"[DEBUG] for read_process_memory in bp_set_sw. Error code: {kernel32.GetLastError()}")

                return False
            
            return True


    # FUNCTION: bp_del_sw
    # INPUT: None
    # PROCESS:
    #   a) restore original byte at breakpoint address
    #   b) remove breakpoint address from list of active breakpoints
    # OUTPUT: None
    def bp_del_sw(self):
        # restore original byte at breakpoint address
        self.write_process_memory(self.exception_address, self.software_breakpoints[self.exception_address][1])
        
        # remove the address from list of active software breakpoints
        del self.software_breakpoints[self.exception_address]

#############################################################################
#                                                                           #
#                            HARDWARE BREAKPOINTS                           #
#                                                                           #
#############################################################################

    # FUNCTION: bp_set_hw
    # INPUT:
    #   address : memory address to set breakpoint at
    #   length  : size of the membory location ad specified address
    #       1 byte      - 00
    #       2 bytes     - 01
    #       4 bytes     - 11
    #   condition : condition to break on
    #       HW_EXECUTE  - 00
    #       HW_WRITE    - 01
    #       HW_ACCESS   - 11 i.e. read or write but not execute
    # PROCESS:
    #   a) check for available debug address register
    #   b) enumerate over each thread of the process and:
    #       b1) set debug control register bit corresponding to debug address register
    #       b2) load debug address register with memory address to set breakpoint at
    #       b3) set condition and length associated with breakpoint
    #       b4) update the thread context thus updating values of debug registers
    # OUTPUT: success status
    def bp_set_hw(self, address, length, condition):
        # Check for a valid length value
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1

        # Check for valid condition
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False

        # Check for available debug address register slots
        if 0 not in self.hardware_breakpoints:
            available = 0
        elif 1 not in self.hardware_breakpoints:
            available = 1
        elif 2 not in self.hardware_breakpoints:
            available = 2
        elif 3 not in self.hardware_breakpoints:
            available = 3
        else:
            return False

        '''
        layout of Debug Register 7 (DR7) a.k.a. Debug Control Register:
         _____________________________________________________________________________________________
        | L | G | L | G | L | G | L | G |         | Type | Len | Type | Len | Type | Len | Type | Len |
        |___|___|___|___|___|___|___|___|_________|______|_____|______|_____|______|_____|______|_____|
        | D | D | D | D | D | D | D | D |         |      |     |      |     |      |     |      |     |
        | R | R | R | R | R | R | R | R |         | DR 0 | DR0 | DR 1 | DR1 | DR 2 | DR2 | DR 3 | DR3 |
        | 0 | 0 | 1 | 1 | 2 | 2 | 3 | 3 |         |      |     |      |     |      |     |      |     |
        |___|___|___|___|___|___|___|___|_________|______|_____|______|_____|______|_____|______|_____|
          0   1   2   3   4   5   6   7   8 - 15   16-17  18-19  20-21 22-23  24-25 26-27  28-29 30-31

        [!!] bits 32 - 63 are not used (as the number of debug resgisters is same as that in x86)
        '''

        # We want to set the debug register in every thread
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id)

            # Enable the appropriate flag in DR7 regiset to set the breakpoint
            context.Dr7 |= 1 << (available * 2)

            # Save the address of the breakpoint in the free debug address register found
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 = address

            # Set the breakpoint condition
            context.Dr7 |= condition << ((available * 4) + 16)

            # Set the length
            context.Dr7 |= length << ((available * 4) + 18)

            # Set thread context with the break set
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        # Update the internal hardware breakpoint array at the used slot index
        self.hardware_breakpoints[available] = (address, length, condition)

        return True

    # FUNCTION: bp_del_hw
    # INPUT:
    #   slot : represents debug address register used for hardware breakpoint
    # PROCESS:
    #   a) clear debug address register value
    #   b) clear debug control register bit corresponding to debug address register
    #   c) clear debug control register bits for condition and length of breakpoint
    #   d) remove breakpoint from list of hardware breakpoints
    # OUTPUT: success status
    def bp_del_hw(self, slot):
        # Disable the breakpoint for all active threads
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id)

            # Reset the flags to remove the breakpoint
            context.Dr7 &= ~(1 << (slot * 2))

            # Zero out the address
            if slot == 0:
                context.Dr0 = 0
            elif slot == 1:
                context.Dr1 = 0
            elif slot == 2:
                context.Dr2 = 0
            elif slot == 3:
                context.Dr3 = 0

            # Remove the condition flag
            context.Dr7 &= ~(3 << ((slot * 4) + 16))

            # Remove the length flag
            context.Dr7 &= ~(3 << ((slot * 4) + 18))

            # Reset the thread's context with the breakpoint removed
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        # remove the breakpoint from the internal list
        del self.hardware_breakpoints[slot]

        return True

#############################################################################
#                                                                           #
#                            MEMORY BREAKPOINTS                             #
#                                                                           #
#############################################################################

    # FUNCTION: bp_set_mem
    # INPUT:
    #   address : memory address to set breakpoint at
    #   size : size of memory region to guard
    # PROCESS:
    #   a) retrieve information related to provided address
    #   b) while the memory page lies inside memory region to guard
    #       b1) store the current page address in list tracking pages guarded by debugger
    #       b2) mark the PAGE_GUARD permissions for current page
    #       b3) store the related information in a data structure tracking memory breakpoints
    # OUTPUT: success status
    def bp_set_mem(self, address, size):
        mbi = MEMORY_BASIC_INFORMATION64()

        _VirtualQueryEx             = kernel32.VirtualQueryEx
        _VirtualQueryEx.argtypes    = [HANDLE, LPCVOID, POINTER(MEMORY_BASIC_INFORMATION64), SIZE_T]
        _VirtualQueryEx.restype     = SIZE_T

        # If VirtualQueryEx() fails to populate entire MEMORY_BASIC_INFORMATION64 structure
        # return False
        if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            return False
        
        current_page = mbi.BaseAddress

        # Set permissions on all pages affected by memory breakpoint
        while current_page <= address + size:
            # Add the page to list of our guarded pages
            self.guarded_pages.append(current_page)

            _VirtualProtectEx = kernel32.VirtualProtectEx
            _VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, POINTER(DWORD)]
            _VirtualProtectEx.restype = BOOL

            # Store old protection modes and guard the page
            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process, current_page, size, mbi.Protect | PAGE_GUARD, byref(old_protection)):
                return False
            current_page += self.page_size

        # add the memory breakpoint to the list
        self.memory_breakpoints[address] = (address, size, mbi, old_protection)

        return True

    # FUNCTION: bp_del_mem
    # INPUT:
    #   address : location of memory breakpoint
    # PROCESS:
    #   a) retrive information related to memory breakpoint
    #   b) delete memory breakpoint's associated entries in internal data structures
    # OUTPUT: None
    def bp_del_mem(self, address):
        # get size of memory region guarded
        size = self.memory_breakpoints[address][1]
        
        # retrieve the MEMORY_BASIC_INFORMATION associated with given memory address
        mbi = self.memory_breakpoints[address][2]

        # remove memory pages from list of guarded page
        current_page = mbi.BaseAddress 
        while current_page <= address + size:
            self.guarded_pages.pop()
            current_page += self.page_size

        # remove the memory breakpoint from the list
        del self.memory_breakpoints[address]