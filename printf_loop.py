from ctypes import *
import time

msvcrt  = cdll.msvcrt
counter = 0

while 1:
    msvcrt.printf("Loop iteration {0}\n".format(counter).encode())
    msvcrt.puts(b"Apple")
    time.sleep(2)
    counter += 1