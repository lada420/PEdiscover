import argparse

def CreateParser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", help="Specifies filename", dest="filename", required=True, metavar="--file")
    parser.add_argument("-fd", help = "Shows file header data", action="store_true")
    parser.add_argument("-od", help = "Shows optional header data", action="store_true")
    parser.add_argument("-i", help = "Shows import addressing table", action="store_true")
    parser.add_argument("-x", help = "Shows hex dump", action="store_true")
    return parser

