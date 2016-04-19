#!/usr/bin/env python3
import selinux
import sepolicy  

import pickle
import networkx as nx

import os, sys, inspect
# use this if you want to include modules from a subfolder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"setools")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import setools

import policy_data_collection as data
import evaluation_functions as evaluation
import domain_grouping as grouping

from collections import defaultdict


def get_writes_to(TCB):
	writes = defaultdict(set)
	tcb_writes = defaultdict(int)
	#TODO> distinguish between entrypoints and resources -- entrypoints are a big NO-NO
	write_perms = {"write", "append"}
	for (u, v, data) in G.in_edges_iter(TCB,data=True):
		if (write_perms.issubset(data.get("file", {}))):
			writes[u].add(v)
			tcb_writes[v] += 1

	return writes, tcb_writes

def get_transitions(G, TCB):
	TCB_additions = set()
	# dynamic transitions
	for (u, v, data) in G.in_edges_iter(TCB,data=True):
		if ("dyntransition" in data.get("process", {}) and
			u not in TCB):
			#"setcurrent" in (G.get_edge_data(u, u, {}).get("process", {}))):
			TCB_additions.add(u)

	return TCB_additions

TCB_names = {"application", "authlogin", "clock", "fstools", "getty", "hostname", "hotplug", "init", "ipsec", "iptables", "kdbus", "libraries", "locallogin", "logging", "lvm", "miscfiles", "modutils", "mount", "netlabel", "selinuxutil", "setrans", "sysnetwork", "systemd", "udev", "unconfined", "userdomain", "bootloader", "consoletype", "dmesg", "netutils", "sudo", "su", "usermanage", "seunshare", "base"}

'''file = open('data/rules_grouping_file_process.bin', 'rb')
G_g = pickle.load(file)
file.close()
'''
file = open('data/rules_file_process.bin', 'rb')
G = pickle.load(file)
file.close()


domain_grouping = grouping.group_types_cil()

TCB = set()

for name in TCB_names:
	group = domain_grouping.get(name, None)
	if group:
		TCB.add(group)
	#else:
	#	print("Could not find: " + name)



TCB_domains, TCB_resources = grouping.get_types(TCB)
new = get_transitions(G, TCB_domains)
#print(TCB_domains)
print(new)

entrypoints_dict = evaluation.find_entrypoints_to(G,TCB_domains)
entrypoints = set(entrypoints_dict.keys())

non_entry = TCB_resources - entrypoints
#print(TCB_resources & entrypoints)

# important !!!
#print("\n".join([x + " > " + ", ".join(entrypoints_dict[x]) for x in entrypoints-TCB_resources]))

print([x for x in non_entry if "exec_t" in x])
'''writes,tcb_writes = get_writes_to(TCB_resources)

#print results sorted according to "value" length
for key,value in sorted(writes.items(), key=lambda x: len(x[1])):
	print(key+":")
	print("\t" + ", ".join(value))
	'''
#esults, transitions = evaluation.find_type_transition_execution(G_g)

#results2, suspicious = evaluation.expand_type_transition_execution(G,transitions)
#print(results-results2)
#print("\n\n".join([str(x)+" > " + ", ".join(y) for x,y in suspicious_p.items() if len(y) > 5]))


#print("\n".join([str(x) for x in susp]))

