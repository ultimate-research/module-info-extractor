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
    global instructions_run
    instructions_run += 1

    if address == SMASH_REGISTER_MODULE:
        register_module_replacement(uc)
    elif address == SMASH_REGISTER_FUNCTION:
        register_function_replacement(uc)
    return True

file_handle = open('./main_200.elf', 'rb')

elf = ELFFile(file_handle)
sections = list(elf.iter_sections())

entry = 0x01925bd0

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

uc.mem_map(0, 0x06704000)

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

print(hexlify(uc.mem_read(0x01925bd0, 4)))
print(f'JUMP Entrypoint: {entry:08X}')
try:
    uc.emu_start(entry, 0x8009F6CC, timeout=2*UC_SECOND_SCALE)
except unicorn.UcError as e:
    print(f"ERROR: {e}")

print(f'Ran {instructions_run} instructions')
file_handle.close()
