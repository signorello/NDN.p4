import os.path, time
import argparse
import datetime
from os.path import expanduser
from crcmod.predefined import *
import sys
import crcmod.predefined

table_name = "fib_table"
action_name = "set_egr"
max_components = 4

def parse_args():
    usage = """Usage: createFIBrules --fib fib.txt --cmd commands.txt [-t table_name] [-a action_name] [-c max_components]
    fib.txt contains the FIB entries listed into separate lines
    commands.txt is the ouput file the produced command rule will be appended to
    """

    parser = argparse.ArgumentParser(usage)

    parser.add_argument('--fib', help='file containing the FIB records',
                        type=str, action="store", required=True)
    parser.add_argument('--cmd', help='file FIB rules will be appended to',
                        type=str, action="store", required=True)
    parser.add_argument('-t', help='Name of the table to be used into the output file records',
                            type=str, action="store", dest="table_name")
    parser.add_argument('-a', help='Name of the action to be used into the output file records',
                            type=str, action="store", dest="action_name")
    parser.add_argument('-c', help='max number of name components supported by the device to be programmed',
                            type=int, action="store", dest="max_components")

    return parser.parse_args()

def convert_rules(fib_file, cmd_file):
    if not os.path.isfile(fib_file):
            print "File %s does not exist" % fib_file
	    sys.exit(-1)
    else:
      print "Reading FIB entries from %s" % fib_file

    print "Appending commands to %s" % cmd_file

    out_file = open(cmd_file, 'a')

    lines = [line.rstrip('\n') for line in open(fib_file)]

    for entry in lines:
      process_entry(entry, out_file)

    out_file.close()

# Entry priority is assigned as follows:
# priority = max_components - num_components + 1 
# lower values give higher priority
def process_entry(entry, out_file):
    print 'Entry: \" %s \" maps into:' % entry
    rule = entry.split(' ')
    name = rule[0]
    iface = int(rule[1])

    name_components = name.split('/')
    name_components.reverse()
    name_components.pop()
    name_components.reverse()

    prefix_ncomp = len(name_components)

    hash_name = compute_hash(name,name_components) 
    needed = max_components - prefix_ncomp + 1
    i=0
    ternary_mask = '0&&&0 '
    masks_str = ''.join(ternary_mask * max_components)
    masks = masks_str.split(" ")
    masks[prefix_ncomp - 1] = str(hash_name) + '&&&0xffff'
    masks.pop()
    masks_str = " ".join(masks)
    
    while i < needed:
      # table_add fib_table set_egr 2 0&&&0 0&&&0 0&&&0 0&&&0 3157158118&&&16 => 1 1
      rule = 'table_add %s %s %d %s => %d %d\n' % (table_name, action_name, prefix_ncomp + i, masks_str, iface, needed)
      out_file.write(rule)
      print '\t' + rule
      i += 1

# I'm making it simple, indeed it should be more complicated, i.e.,
# computing crc32 on the whole name and smaller hashes on the shorter
# prefix-names
# I should parametrize such function so to take the algorithm type as arguments too
def compute_hash(name, name_components):
    crc16 = crcmod.predefined.mkCrcFun('crc-16')
    return crc16("".join(name_components))

def main():
    global table_name, action_name, max_components

    args = parse_args()
    if args.table_name is not None:
      table_name = args.table_name
    if args.action_name is not None:
      action_name = args.action_name
    if args.max_components is not None:
      max_components = args.max_components

    convert_rules(args.fib, args.cmd)

if __name__ == '__main__':
    main()
