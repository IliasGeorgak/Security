##Identifying the vulnerability
###After first inspecting the code it became apparent that the memory area where the "Name" array is stored in the stack is unprotected when it comes to reading, writing and executing code that might be stored there. It was also apparent that the readString function is compromised since it only uses gets without checking the length of the string provided. The arbitrary length string is stored in a 32 byte buffer before having 128 bytes transfered to the Name array. This meant the buffer could be overflowed, filling it with a malicious payload and overwriting the return address of the readString function with the address of the Name array since the payload will have already been written there and that part of the stack is executable.

##Exploiting the vulnerable code
###Using gdb and after setting a breakpoint before the return statement in the readString function we get more info about this specific stack frame and can locate the address where the eip pointer is stored. Next we find where the buffer is stored using the x command as well as the Name array. All that is left is creating the payload.

##Execution
###python3 was used to create a binary file with the payload through byte arrays. To use the exploit first the payload is saved to the file and then provided to the greeter as input.
```bash 
python3 mal.py
(cat payload.bin ; cat)| ./Greeter
```
##Notes
###For some reason when a shell opens through the compromised Greeter we first need to type a new line and then it starts working. 
