import pyjsonrpc
import argparse

import squirrelflowdb

parser = argparse.ArgumentParser()
args = parser.parse_args()

def main():
    squirrelflow_db = squirrelflowdb.SquirrelFlowDB("rule_x86/")
    insn_set = {"55", "d1d9"}
    squirrelflow_db.check_rules("X86", insn_set)
    print(squirrelflow_db.get_rule("X86", "55"))


if __name__ == "__main__":
    main()
