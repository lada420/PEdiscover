class dicts(object):
    def __init__(self):
        self.subsdict ={0:"Unknown subsystem.", 1:"No subsystem required (device drivers and native system processes).",3:"Windows character-mode user interface (CUI) subsystem.",
           5:"OS/2 CUI subsystem.",7:"POSIX CUI subsystem.",9:"Windows CE system.",10:"Extensible Firmware Interface (EFI) application.", 11:"EFI driver with boot services.",
           12:"EFI driver with run-time services.", 13:"EFI ROM image.", 14:"Xbox system.", 16:"Boot application."}
        self.machinedict = {'0x0':"Impossible to define machine", '0x1d3':"Matsushita AM33", '0x8664':"x64", '0x1c0':"ARM little endian", '0xaa64':"ARM64 little endian", '0xebc':"EFI byte code",
               '0x14c':"Intel 386 or later processors and compatible processors", '0x200':"Intel Itanium processor family", '0x9041':"Mitsubishi M32R little endian ",
               '0x266':"MIPS16", '0x366':"MIPS with FPU", '0x466':"MIPS16 with FPU", '0x1f0':"Power PC little endian", '0x1f1':"Power PC with floating point support Power PC with floating point support ",
               '0x166':"MIPS little endian", '0x5032':"RISC-V 32-bit address space", '0x5064':"RISC-V 64-bit address space", '0x5128':"RISC-V 128-bit address space", '0x1a3':"Hitachi SH3 DSP",
               '0x1a6':"Hitachi SH4", '0x1a8':"Hitachi SH5", '0x1c2':"Thumb", '0x169':"MIPS little-endian WCE v2"}
        self.dllchar1dict = {8:"The image is terminal server aware.", 2:"A WDM driver."}
        self.dllchar2dict = {8:"Do not bind the image.v", 4:"The image does not use structured exception handling (SEH). No handlers can be called in this image.",
                2:"The image is isolation aware, but should not be isolated.", 1:"The image is compatible with data execution prevention (DEP)."}
        self.dllchar3dict = {8:"Code integrity checks are forced." , 4:"The DLL can be relocated at load time."}