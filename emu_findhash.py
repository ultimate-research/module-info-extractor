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

SMASH_REGISTER_MODULE = 0x29570e0
SMASH_REGISTER_FUNCTION = 0x2957670
# FIGHTER_STATUS_DAMAGE_WORK_FLOAT_VECOR_CORRECT_STICK_X
SMASH_STRING_OFFSET = 0x382c816
SMASH_STRING_HASH = 0xA4D50A730E36970E
SMASH_STRING_CRC = 0x1bc1d3d4

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

def register_module_replacement(uc):
    global current_id
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2)
    x3 = uc.reg_read(UC_ARM64_REG_X3)
    name = uc_get_string(x2)
    print(f"Module {name:30} {x3:08X}")
    uc_write_u64(x0, current_id)
    module_names.append(name)
    module_functions.append([])
    current_id += 1
    uc_return()

def register_function_replacement(uc):
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2)
    name = uc_get_string(x1)
    module_id = uc_read_u64(x0)
    module_functions[module_id].append((name, x2))
    print(f"    Function {name:24} {x2:08X}")
    uc_return()

def hook_code(uc, address, size, user_data):
    if address == 0xDEADBEEF00000000:
        print("Returned")

    #if address == SMASH_REGISTER_MODULE:
    #    register_module_replacement(uc)
    #elif address == SMASH_REGISTER_FUNCTION:
    #    register_function_replacement(uc)
    return True

file_handle = open('./main_200.elf', 'rb')

elf = ELFFile(file_handle)
sections = list(elf.iter_sections())

entry = 0x01925bd0

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

print(f"Input string - {uc_get_string(SMASH_STRING_OFFSET)}")
with open('main_200_function_list.txt') as f:
    functions = [int(i.strip(), 16) for i in f.read().split('\n') if not i.strip() == ""]

from progress.bar import IncrementalBar as Bar

successful = []
crc_success = []
for offset in Bar('Tested %(index)d/%(max)d functions', suffix='%(percent).1f%% - %(eta)ds remaining', max=len(functions)).iter(functions):
    entry = offset
    try:
        # Pass string as first arg
        uc.reg_write(UC_ARM64_REG_X0, SMASH_STRING_OFFSET)
        # Pass length as second arg (might not be used)
        uc.reg_write(UC_ARM64_REG_X1, len(uc_get_string(SMASH_STRING_OFFSET)))
        uc.emu_start(entry, 0x8009F6CC, timeout=int(0.02*UC_SECOND_SCALE))
    except unicorn.UcError as e:
        # Hope it returned, read return val
        retVal = uc.reg_read(UC_ARM64_REG_X0)
        if retVal == SMASH_STRING_HASH:
            successful.append(offset)
        if retVal == SMASH_STRING_CRC:
            crc_success.append(offset)

print("Successful mystery hash functions:")
for i in successful:
    print(hex(i))

print("Successful CRC functions:")
for i in crc_success:
    print(hex(i))

#try:
#    uc.emu_start(entry, 0x8009F6CC, timeout=2*UC_SECOND_SCALE)
#except unicorn.UcError as e:
#    print(f"Result: {hex(uc.reg_read(UC_ARM64_REG_X0))}")
    #print(f"Error: {e}")

#print(f'Ran {instructions_run} instructions')
file_handle.close()
