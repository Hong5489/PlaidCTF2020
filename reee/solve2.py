from z3 import *
elf = open("./reee2",'r').read()
data = bytearray(elf[0x8eb:])

key = 0x50
length = 33
solver = Solver()

flag = [BitVec('b%i' % i,8) for i in range(length)]
inp = [BitVec('b%i' % i,8) for i in range(length)]

for i in range(0x539):
	for j in range(length):
		inp[j] = inp[j] ^ key
		key = key ^ inp[j]

for i in range(length):
	solver.add(data[i] == inp[i])
	solver.add(And(flag[i] >= 33,flag[i] <= 126))
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