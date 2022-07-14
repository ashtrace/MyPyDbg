import my_debugger

debugger = my_debugger.debugger()

pid = input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))

printf_address = debugger.func_resolve("msvcrt.dll", "printf")

print(f"[*] Address of printf: {hex(printf_address)}")

debugger.bp_set_sw(printf_address)

debugger.run()