from elftools.elf.elffile import ELFFile
from binascii import hexlify

from unicorn import *
from unicorn.arm64_const import *

import struct
import re

global instructions_run, current_id
instructions_run = 0
current_id = 0
module_functions = []
module_names = []

SMASH_HASH_ADDR = 0x2b569a0
SMASH_REGISTERING_FUNCTION = 0x1913930
SMASH_REGISTER_FUNCTION = 0x2957450
SMASH_REGISTER_CATEGORY = 0x29570e0

#SMASH_REGISTER_MODULE = 0x29570e0
#SMASH_REGISTER_FUNCTION = 0x2957670
# FIGHTER_STATUS_DAMAGE_WORK_FLOAT_VECOR_CORRECT_STICK_X
#SMASH_STRING_OFFSET = 0x382c816
#SMASH_STRING_HASH = 0xA4D50A730E36970E
#SMASH_STRING_CRC = 0x1bc1d3d4

def uc_get_string(addr):
    s = ""
    c = uc.mem_read(addr, 1)
    while c != b'\x00':
        s += c.decode('latin8')
        addr += 1
        c = uc.mem_read(addr, 1)
    return s

def uc_write_u64(addr, num):
    uc.mem_write(addr, struct.pack("<Q", num))

def uc_read_u64(addr):
    return struct.unpack("<Q", uc.mem_read(addr, 8))[0]

def uc_return():
    lr = uc.reg_read(UC_ARM64_REG_LR)
    uc.reg_write(UC_ARM64_REG_PC, lr)

def uc_write_string(string, addr):
    uc.mem_write(addr, string.encode('utf8') + b'\0')

def hook_code(uc, address, size, user_data):
    global instructions_run
    instructions_run += 1

    return True

file_handle = open('./main_200.elf', 'rb')

elf = ELFFile(file_handle)
sections = list(elf.iter_sections())

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

uc.mem_map(0, 0x06704000)
# protect rodata just in case
uc.mem_protect(0x037b1000, 0x818000, UC_PROT_READ)

# Setup stack
uc.mem_map(0x0F000000, 0x01000000) # Stack
uc.reg_write(UC_ARM64_REG_SP, 0xFF00000) # Default stack pointer

for i, section in enumerate(sections):
    if section["sh_addr"] == 0 and section.name != ".text":
        continue
    print(f'LOAD {i:2} {section["sh_flags"] & 0x7:03b} {section["sh_addr"] + 0x100000:08X} {section["sh_addr"] + section.data_size + 0x100000:08X} {section.name}')
    uc.mem_write(section["sh_addr"] + 0x100000, section.data())

def empty_func(a,b,c,d):
    pass

# Map HOOK_CODE to an empty function, which fixes the fact unicorn's
# reg read's PC value doesn't update after the first jal cause reasons???
uc.hook_add(UC_HOOK_CODE, hook_code)

#entry = SMASH_REGISTERING_FUNCTION

#print(f"JUMP entry {entry:X}")
#try:
#    uc.emu_start(entry, 0x8009F6CC, timeout=2*UC_SECOND_SCALE)
#except unicorn.UcError as e:
#    #print(f"Result: {hex(uc.reg_read(UC_ARM64_REG_X0))}")
#    print(f"Error: {e}")

from progress.bar import IncrementalBar as Bar

# map some memory for just holding strings
uc.mem_map(0x6900000000, 0x4000)

with open('strings.txt', 'r') as f:
    strings = [i.strip() for i in f.read().split('\n') if i.strip() != ""]
with open('string_hashes.csv', 'w') as f:
    for string in Bar('Hashed %(index)d/%(max)d strings', suffix='%(percent).1f%% - %(eta)ds remaining', max=len(strings)).iter(strings):
        uc_write_string(string, 0x6900000000)
        try:
            uc.reg_write(UC_ARM64_REG_X0, 0x6900000000)
            uc.reg_write(UC_ARM64_REG_X1, len(string))
            uc.reg_write(UC_ARM64_REG_LR, 0xDEADBEEFDEADBEEF)
            uc.emu_start(SMASH_HASH_ADDR, 0x8009F6CC, timeout=2*UC_SECOND_SCALE)
        except unicorn.UcError as e:
            # hopefully it succeeded enough to give us the hash
            hash = uc.reg_read(UC_ARM64_REG_X0)
            print(f"0x{hash:016X},\"{string}\"", file=f)

print(f'Ran {instructions_run} instructions')
file_handle.close()
