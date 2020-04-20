check_flag = open("./check_flag",'r').read()
elf = open("./reee",'r').read()
start,end = 0x6e5,0x93f

new_elf = elf[:start] + check_flag + elf[end:]

print len(check_flag)
print len(elf[start:end])
open("./reee2",'w').write(new_elf)