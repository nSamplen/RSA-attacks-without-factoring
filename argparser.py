import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-enc", "--enc", action="store_true")
parser.add_argument("-dec", "--dec", action="store_true")
parser.add_argument("-sgn", "--sgn",action="store_true")
parser.add_argument("-chcksign", "--chcksign",action="store_true")
parser.add_argument("--filepath",help="File to ecrypt/decrypt/sign")
parser.add_argument("--sgnpath", help="Path to the signarute file")

