inp = bytearray("pctf{ok_nothing_too_fancy_there!}")
key = 0x50
for i in range(0x539):
	for j in range(len(inp)):
		inp[j] = inp[j] ^ key
		key = key ^ inp[j]

print repr(inp)