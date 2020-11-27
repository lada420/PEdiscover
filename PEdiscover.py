#!/usr/bin/python3
import pefile
from typing import Dict, Any, Union
from inits import *
from parser import *
import sys
import os
import math

info_list = info_set()

def show_file_magic():
    num_of_sections = pe.FILE_HEADER.NumberOfSections
    print("Number of section:", num_of_sections)
    machine = hex(pe.FILE_HEADER.Machine)
    print("Machine for this PE: " + info_list.machinedict[machine])

def show_optional_header():
    image_base = hex(int(pe.OPTIONAL_HEADER.image_base))
    print("Image base of PE: " + image_base)
    EntryPoint_Address = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.image_base)
    print("Entry point address: " + EntryPoint_Address)

    base_of_code = hex(pe.OPTIONAL_HEADER.base_of_code + pe.OPTIONAL_HEADER.image_base)
    base_of_data = hex(pe.OPTIONAL_HEADER.base_of_data + pe.OPTIONAL_HEADER.image_base)
    print("Base of code section: " + base_of_code)
    print("Base of data section: " + base_of_data)

    heap_free_space = hex(pe.OPTIONAL_HEADER.SizeOfStackCommit - pe.OPTIONAL_HEADER.SizeOfStackReserve)
    stack_free_space = hex(pe.OPTIONAL_HEADER.SizeOfStackReserve - pe.OPTIONAL_HEADER.SizeOfStackCommit)
    print("Free stack space : " + stack_free_space)
    print("Free heap space: " + heap_free_space)

    print("PE subsystem:", info_list.subsdict[pe.OPTIONAL_HEADER.Subsystem])

    DllCharacteristics = int(pe.OPTIONAL_HEADER.DllCharacteristics)
    dllchar1 = DllCharacteristics // 0x1000
    DllCharacteristics %=0x1000
    dllchar2 = DllCharacteristics // 0x100
    DllCharacteristics %= 0x100
    dllchar3 = DllCharacteristics // 0x10
    print ("DLL charachteristics: " + info_list.dllchar1dict[dllchar1] + " " + info_list.dllchar2dict[dllchar2] + " " + info_list.dllchar3dict[dllchar3])

def show_import_table():
    pe.parse_data_directories()
    print("Import table containment:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll)
        for imp in entry.imports:
            print('\t', hex(imp.address), imp.name)

def get_hex_dump():
    file = args.filename
    bytelist = bytearray()
    with open(file, 'rb') as bytes:
        for byte in bytes:
            bytelist.extend(byte)
    nl = 0
    byte_str = str()
    for byte in bytelist:
        byte_str += " {}" .format(hex(byte))
        nl+=1
        if nl == 16:
            print(byte_str)
            byte_str = ''
            nl = 0

if __name__ == "__main__":
    parser = CreateParser()
    args = parser.parse_args()
    pe = pefile.PE(args.filename)

    if args.fd:
        show_file_magic()
    if args.od:
        show_optional_header()
    if args.i:
        show_import_table()
    if args.x:
        get_hex_dump()