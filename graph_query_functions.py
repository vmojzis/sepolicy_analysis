#!/usr/bin/env python3
import selinux
import sepolicy  

import networkx as nx

from collections import defaultdict
import evaluation_functions as graph
from security_related import get_security_types


''' 
User defined functions HAVE TO adhere to following naming scheme

 "funciton_name"_query(graph)
 	returns list/set of results 
 "function_name"_string(results)
 	"results" is object returned by corresponding _query function
 	returns string
 "function_name"_diff(results1, results2)
 	given results (whole lists returned by _query funcion) computed over 2 different graphs
 	returns list/set (same as _query function)
 	Aimed at regression testing
'''

# find all types corresponding to executables, that can be written to
# returns dictionary (execuatable types as keys, types with write permission as values)
def write_executable_query(G):
	return graph.find_writable_executables(G)

# Find domain transitions via entrypoints that can be rewritten by source domain
# This effectively increases reach of source domain by access rights of target domain
def transition_write_query(G):
	transitions = graph.find_type_transitions(G)
	
	results = set()
	for source,target,entry in transitions:
		if ("write" in G.get_edge_data(source,entry, {}).get("file", {})):
			results.add((source,target,entry))
	return results


def write_to_security_query(G):
	domains, resources = get_security_types()
	sec_types = domains | resources
	#results =  graph.find_edges_permission_set_to(G, sec_types, "file", {"write"})

	results = defaultdict(set)
	#TODO> distinguish between entrypoints and resources -- entrypoints are a big NO-NO
	for (u, v, data) in G.in_edges_iter(sec_types,data=True):
		if (("write" in data.get("file", {})) and
			u not in sec_types):
			results[u].add(v)

	return results

#print results sorted according to "value" length
def write_to_security_string(results):
	strings = []
	for key,value in sorted(results.items(), key=lambda x: len(x[1])):
		strings.append(key + "\n\t\t" + ", ".join(value))

	return "\t" + "\n\t".join(strings)

#print results sorted according to "value" length
def write_to_security_string(results):
	strings = []
	for key,value in sorted(results.items(), key=lambda x: len(x[1])):
		strings.append(key + "\n\t\t" + ", ".join(value))

	return "\t" + "\n\t".join(strings)


def append_to_security_query(G):
	domains, resources = get_security_types()
	sec_types = domains | resources
	#results =  graph.find_edges_permission_set_to(G, sec_types, "file", {"write"})

	results = defaultdict(set)
	#TODO> distinguish between entrypoints and resources -- entrypoints are a big NO-NO
	for (u, v, data) in G.in_edges_iter(sec_types,data=True):
		if (("append" in data.get("file", {})) and
			u not in sec_types):
			results[u].add(v)

	return results

def append_to_security_string(results):
	return write_to_security_string(results)