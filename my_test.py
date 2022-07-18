# SIMPLE TEST SCRIPT TO VALIDATE FEATURES ADDED

from my_debugger_defines import *
import my_debugger

debugger = my_debugger.debugger()

pid = input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))

printf_address = debugger.func_resolve("msvcrt.dll", "printf")

print(f"[*] Address of printf: {hex(printf_address)}")

# To set software breakpoint uncomment following statement
#debugger.bp_set_sw(printf_address)

# To set hardware breakpoint uncomment following statement
#debugger.bp_set_hw(printf_address, 1, HW_EXECUTE)

# To set memory breakpoint uncomment following statement
#debugger.bp_set_mem(printf_address, 10)

debugger.run()