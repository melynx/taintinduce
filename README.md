# taintinduce
TaintInduce is a project which aims to automate the creation of taint propagation rules for unknown instruction sets.

## References
One Engine To Serve 'em All: Inferring Taint Rules Without Architectural Semantics

Zheng Leong Chua, Yanhao Wang, Teodora Băluță, Prateek Saxena, Zhenkai Liang, Purui Su. 

In the Network and Distributed System Security Symposium 2019, San Diego, CA, US, Feb 2019. 

## Disclaimer
We are currently in the process of rewriting the prototype to better serve our goal of providing an online taint service for different architectures.
For people who are interested in the implementation used in the paper, feel free to contact us.

## Requirements
### Python
- capstone
- keystone-engine
- unicorn
- z3
- pyjsonrpc
##### Issue with virtual env (Ubuntu 16.04, Python 2.7.12)
When installing `capstone` and `keystone-engine` with `pip` in a virtual environment, the shared library files are expected to be in a folder like `~/.virtualenvs/<virtual_env>/lib/python2.7/site-packages/capstone`. If not, you might run into an import error:
`ImportError: ERROR: fail to load the dynamic library.`

A quick solution is to find where the library is and copy it to the expected path. For example, `find - name libcapstone*` inside `~/.virtualenvs/<virtual_env>`  and copy it to `~/.virtualenvs/<virtual_env>/lib/python2.7/site-packages/capstone`.

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

