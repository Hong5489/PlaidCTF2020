# reee
## Story
```
Tired from all of the craziness in the Inner Sanctum, you decide to venture out to the beach to relax. You doze off in the sand only to be awoken by the loud “reee” of an osprey. A shell falls out of its talons and lands right where your head was a moment ago. No rest for the weary, huh? It looks a little funny, so you pick it up and realize that it’s backwards. I guess you’ll have to reverse it.
```
## Problem Details
[Download](./reee)
```
Hint: Flag format
The flag format is pctf{$FLAG}. This constraint should resolve any ambiguities in solutions.
```
Running `file` command:
```bash
file reee
reee: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3ccec76609cd013bea7ee34dffc8441bfa1d7181, stripped
```
Running `strings` command nothing interesting:
```
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
__libc_start_main
__gmon_start__
GLIBC_2.2.5
...
need a flag!
Correct!
Wrong!
...
```
Test running:
```
./reee
need a flag!
Segmentation fault

./reee flag
Wrong!

```
Seems the flag is the program argument

## Analyse
It's open it in Ghidra and analyse it!

**entry function:**
```c
void entry(undefined8 uParm1,undefined8 uParm2,undefined8 uParm3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];
  
  __libc_start_main(FUN_0040064e,in_stack_00000000,&stack0x00000008,FUN_00400940,FUN_004009b0,uParm3
                    ,auStack8);
}
```
Looks like the `main` function is located at `FUN_0040064e`

*Note: I modified the code to more readable, it is not the original code*
**main function:**
```c
void main(int iParm1)

{
  code cVar1;
  long valid;
  int j;
  int i;
  
  if (iParm1 < 2) {
    puts("need a flag!");
  }
  i = 0;
  while (i < 0x7a69) {
    j = 0;
    while (j < 0x228) {
      cVar1 = unscramble(check_flag[j]); 
      							// unscramble the check_flag function 
      check_flag[j] = cVar1;	// Overwrite the function
      j = j + 1;
    }
    i = i + 1;
  }
  valid = check_flag();			// If check_flag return 1 then is valid flag
  if (valid == 0) {
    puts("Wrong!");
  }
  else {
    puts("Correct!");
  }
  return;
}
```
We need to get the unscrambled `check_flag` function to analyse how it works

I'm lazy to analyse the `unscramble` function

So I decided to open it in `GDB Debugger` and set breakpoint to get the function shellcode:
```
gdb ./reee
pwndbg> b * 0x4006db 
Breakpoint 1 at 0x4006db
pwndbg> run flag
Breakpoint * 0x4006db
...
...
pwndbg> dump binary memory check_flag 0x4006e5 0x40093f
```
The `check_flag` function start from 0x4006e5 to 0x40093f

Wrote a simple python script to replace the unscramble `check_flag` to the original ELF:
```python
check_flag = open("./check_flag",'r').read()
elf = open("./reee",'r').read()
start,end = 0x6e5,0x93f

new_elf = elf[:start] + check_flag + elf[end:]
open("./reee2",'w').write(new_elf)
```
Use Ghidra to open the new ELF, we can start analyse the real `check_flag` function!

**check_flag function:**
```c
ulong check_flag(void)

{
  char cVar1;
  char *input;
  long input_length;
  byte bVar5;
  int i;
  int j;
  
  input_length = strlen(input);		// Calculate input length
  bVar5 = 0x50;
  i = 0;
  while (i < 0x539) {				// XORing the input 0x539 times
    j = 0;							// using 0x50 as starting key
    while (j < input_length) {
      input[j] = input[j] ^ bVar5;
      bVar5 = bVar5 ^ input[j];
      j = j + 1;
    }
    i = i + 1;
  }

  i = 0;
  while (i < input_length) {		
  	if(input[i] != (&UNK_004008eb)[i]) // If all XORed input is equal to 
  									   // the memory then input is valid
  		return false
  }
  return true
}
```
## Solving
Looks like we need to calculate the flag based on the memory at 0x4008eb

**Z3 solver** can help us to calculate the flag!

I wrote a [python script](./solve2.py) that calculate the flag using z3:
```py
from z3 import *
elf = open("./reee2",'r').read()
data = bytearray(elf[0x8eb:]) # Get the memory at 0x4008eb (0x8eb in file)

key = 0x50
length = 33 # Guess the flag length is 33
solver = Solver()

# Declare Flag BitVector
flag = [BitVec('b%i' % i,8) for i in range(length)] 
# Declare Input BitVector is same as Flag
inp = [BitVec('b%i' % i,8) for i in range(length)]

for i in range(0x539):			# XOring the input according 
	for j in range(length):		# to the check_flag function
		inp[j] = inp[j] ^ key
		key = key ^ inp[j]

for i in range(length):
	solver.add(data[i] == inp[i]) # Add condition which
								  # input is equal to memory
	# Condition flag is in printable ascii range
	solver.add(And(flag[i] >= 33,flag[i] <= 126))  
# Condition flag is in flag format according to hint
solver.add(flag[0] == ord("p"))					  
solver.add(flag[1] == ord("c"))
solver.add(flag[2] == ord("t"))
solver.add(flag[3] == ord("f"))
solver.add(flag[4] == ord("{"))
solver.add(flag[-1] == ord('}'))

if solver.check() == sat:
	modl = solver.model()
	print("Length: "+str(length))
	print(''.join([chr(modl[f].as_long()) for f in flag]))
for i in range(length):
	flag[i].reset()
	inp[i].reset()
```
After guessing few times the flag length, we found that the flag length is 33:
```bash
python solve2.py 
Length: 33
pctf{ok_nothing_too_fancy_there!}
```
Finally, we get the Flag!!!

## Flag
```
pctf{ok_nothing_too_fancy_there!}
```