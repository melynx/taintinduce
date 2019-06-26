# taintinduce
TaintInduce is a project which aims to automate the creation of taint propagation rules for unknown instruction sets.

## Requirements
### Python2.7
- capstone 
- keystone
- unicorn
- z3
- pyjsonrpc
## Usage
### Set up server(s)

@TODO

### Client
Edit `squirrelflow.cfg`. Put your <server:port> into this configure file.
```
http://127.0.0.1:10004
http://127.0.0.1:10005
```

Init FlowDB with rule directory:
```
from taintinduce.squirrelflowdb import SquirrelFlowDB
FlowDB = SquirrelFlowDB(rule_dir)
```

Check a set of rules: 
```
FlowDB.check_rules(arch, insns)
```
Where `arch` is one of ['X86', 'AMD64', 'ARM64'] and `insns` is a set of instructions (raw bytes).

Get a rule of a given instruction.
```
squirrel_flow = FlowDB.get_rule(arch, insn)
```

## Format of rules
@TODO
