import pefile
from capstone import *
from typing import Dict, Any, Union
from inits import *
from parser import *
import sys
import os
import math


newinit = dicts()


def ShowFile():
    NOS = pe.FILE_HEADER.NumberOfSections
    print "Number of section is:", NOS
    machine = hex(pe.FILE_HEADER.Machine)
    print "Machine for this PE is: " + newinit.machinedict[machine]
def ShowOptional():
    ImageBase = hex(int(pe.OPTIONAL_HEADER.ImageBase))
    print "Image base of PE is: " + ImageBase
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    EntryPoint_Address = hex(entrypoint+pe.OPTIONAL_HEADER.ImageBase)
    print "Entry point address is: " + EntryPoint_Address
    BaseOfCode = hex(pe.OPTIONAL_HEADER.BaseOfCode + pe.OPTIONAL_HEADER.ImageBase)
    BaseOfData = hex(pe.OPTIONAL_HEADER.BaseOfData + pe.OPTIONAL_HEADER.ImageBase)
    print "Base of code address is: " + BaseOfCode
    print "Base of data address is: " + BaseOfData
    reservedstack = pe.OPTIONAL_HEADER.SizeOfStackReserve
    commitstack = pe.OPTIONAL_HEADER.SizeOfStackCommit

    reservedheap = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    commitheap = pe.OPTIONAL_HEADER.SizeOfHeapCommit

    HeapFreeSpace = hex(reservedheap - commitheap)
    StackFreeSpace = hex(reservedstack - commitstack)
    print "Free space on the stack is: " + StackFreeSpace
    print "Free space on the heap is: " + HeapFreeSpace

    subs = pe.OPTIONAL_HEADER.Subsystem
    print "PE subsystem is:", newinit.subsdict[subs]

    DllCharacteristics = int(pe.OPTIONAL_HEADER.DllCharacteristics)
    dllchar1 = DllCharacteristics // 0x1000
    DllCharacteristics %=0x1000
    dllchar2 = DllCharacteristics // 0x100
    DllCharacteristics %= 0x100
    dllchar3 = DllCharacteristics // 0x10

    print "DLL charachteristics: " + newinit.dllchar1dict[dllchar1] + " " + newinit.dllchar2dict[dllchar2] + " " + newinit.dllchar3dict[dllchar3]
def ShowIat():
    pe.parse_data_directories()
    print "Import table containment:"
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print entry.dll
        for imp in entry.imports:
            print '\t', hex(imp.address), imp.name
def GetHex():
    file = args.filename
    bytelist = bytearray()
    with open(file, 'rb') as bytes:
        for byte in bytes:
            bytelist.extend(byte)
    print ' '.join(format(x, '02x') for x in bytelist)
def DisassFromStart():
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    EntryPoint_Address = entrypoint + pe.OPTIONAL_HEADER.ImageBase
    binarycode = pe.get_memory_mapped_image()[entrypoint:entrypoint + args.ds]
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    for instr in disassembler.disasm(binarycode, EntryPoint_Address + args.ds):
        print "%s\t%s" % (instr.mnemonic, instr.op_str)
def DisassFromOffset():
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    EntryPoint_Address = entrypoint + pe.OPTIONAL_HEADER.ImageBase
    binarycode = pe.get_memory_mapped_image()[entrypoint + args.do:entrypoint + args.do + args.o]
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    for instr in disassembler.disasm(binarycode, EntryPoint_Address+args.o):
        print "%s\t%s" % (instr.mnemonic, instr.op_str)



newparser = pars()
parser = pars.CreateParser(newparser)
args = parser.parse_args()
pe = pefile.PE(args.filename)

if args.fd:
    ShowFile()
if args.od:
    ShowOptional()
if args.i:
    ShowIat()
if args.x:
    GetHex()
if args.ds:
    DisassFromStart()
if args.do and args.o:
    DisassFromOffset()
