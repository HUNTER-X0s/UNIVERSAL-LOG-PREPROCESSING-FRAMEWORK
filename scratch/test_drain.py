from ulpf_parser_runtime.drain import DrainParser

d = DrainParser()
r1 = d.parse("Failed password for invalid user admin from 192.168.1.100 port 22 ssh2")
r2 = d.parse("Failed password for invalid user root from 10.0.0.15 port 51234 ssh2")
r3 = d.parse("Connection closed by authenticating user test 192.168.1.50 port 44122 [preauth]")

print("R1 Template:", r1.template)
print("R1 Params:", r1.parameters)
print("R2 Template:", r2.template)
print("R2 Params:", r2.parameters)
print("R2 Cluster size:", r2.cluster_size)
print("R3 Template:", r3.template)
print("Total clusters:", len(d.clusters))
