import pyjsonrpc

g = pyjsonrpc.HttpClient(url="http://localhost:12345")
g._gen_observation("59", "X86")
