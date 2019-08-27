# taintinduce
TaintInduce is a project which aims to automate the creation of taint
propagation rules for unknown instruction sets.

## References
One Engine To Serve 'em All: Inferring Taint Rules Without Architectural
Semantics

Zheng Leong Chua, Yanhao Wang, Teodora Băluță, Prateek Saxena, Zhenkai Liang,
Purui Su. 

In the Network and Distributed System Security Symposium 2019, San Diego, CA,
US, Feb 2019. 

## Disclaimer
We are currently in the process of rewriting the prototype to better serve our
goal of providing an online taint service for different architectures.
For people who are interested in the implementation used in the paper, feel free
to contact us.

## Requirements
### Python3.6
- capstone 
- keystone
- unicorn
- tqdm
- squirrel-framework

## Usage
@TODO
taintinduce.py provides the inference interface and is the CLI tool to generate the rule.
Checkout the --help option on how to use the CLI tool.

##### Issue with virtual env (Ubuntu 16.04, Python 2.7.12)
When installing `capstone` and `keystone-engine` with `pip` in a virtual
environment, the shared library files are expected to be in a folder like
`~/.virtualenvs/<virtual_env>/lib/python2.7/site-packages/capstone`. If not, you
might run into an import error:
`ImportError: ERROR: fail to load the dynamic library.`

A quick solution is to find where the library is and copy it to the expected
path. For example, `find - name libcapstone*` inside
`~/.virtualenvs/<virtual_env>`  and copy it to
`~/.virtualenvs/<virtual_env>/lib/python2.7/site-packages/capstone`.

## Format of rules
@TODO

