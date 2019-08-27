import argparse
import os

import squirrelflow
import taintinduce.pypeekaboo

def train_peekaboo(trace_path):
    # parse the 
    pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('trace_path', type=str, help='Path to a peekaboo trace.')
    parser.add_argument('--output-dir', type=str, default='rules', help='Rules directory.')

    args = parser.parse_args()

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    squirrelflow_db = squirrelflowdb.SquirrelFlowDB(args.output_dir)
    peekaboo = pypeekaboo.PyPeekaboo(args.trace_path)

    insn_set = set()
    for addr in peekaboo.bytesmap:
        bytestring = ''.join(['{:02x}'.format(x) for x in peekaboo.bytesmap[addr]])
        insn_set.add(bytestring)
    print(len(insn_set))

    squirrelflow_db.check_rules(peekaboo.arch_str, insn_set)

if __name__ == "__main__":
    main()
