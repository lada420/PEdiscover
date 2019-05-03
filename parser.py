import argparse
class pars(object):
    def CreateParser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-f", help="Specifies filename", dest="filename", required=True, metavar="--file")
        parser.add_argument("-fd", help = "Shows file header data", action="store_true")
        parser.add_argument("-od", help = "Shows optional header data", action="store_true")
        parser.add_argument("-i", help = "Shows import addressing table", action="store_true")
        parser.add_argument("-x", help = "Shows hex dump", action="store_true")
        parser.add_argument("-ds", help = "Disassembly PE with from entrypoint with specified offset", action="store", type = int)
        parser.add_argument("-do", help = "Specifies the offset from entrypoint for disassembling. Usage with -o", action="store", type = int)
        parser.add_argument("-o", help = "Specifies the range of bytes to be disassembled. Usage with -do", action="store", type = int)
        return parser

