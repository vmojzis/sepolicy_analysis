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
import domain_grouping as grouping

from collections import defaultdict

def expand_type_transition_execution(G, groupped_transitions):
	process_transitions = defaultdict(set)
	#print(groupped_transitions)
	for source_g, target_g in groupped_transitions:
		for source in source_g.types:
			for target in target_g.types:
				#if (source == "accountsd_t" and target == "abrt_helper_t"):
				#		print("DAGFUQ?")
				if ("transition" in G.get_edge_data(source, target, {}).get("process", {})):
					process_transitions[target].add(source)	


	results = set()
	transitions = set()

	'''process_transitions2 = defaultdict(set)
	#old networkx version !!!
	#for (u, v, data) in G.edges_iter(data="process"):
	for (u, v, data) in G.edges_iter(data=True):
		#print(u, " ", v, " ",data)
		if ("transition" in data.get("process", {})):
			process_transitions2[v].add(u)

	for key,value in process_transitions2.items():
		value2 = process_transitions.get(key, None)
		if (not value2):
			print(key)
		if value not in value2:
			print(value, "\n", value2)
	#sys.exit()
	#print("\n".join([str(x) for x in (process_transitions - process_transitions2)]))
	'''
	execute_perms = set(["execute", "read", "getattr"])
	for target,sources in process_transitions.items():
		#find "entrypoint" in target node successors
		
		for succ in G.successors_iter(target):
			if ("entrypoint" in G.get_edge_data(target, succ, {}).get("file", {})):
				#test if sources have "execute" permissions on entrypoint
				for source in sources:
					if(execute_perms.issubset(G.get_edge_data(source, succ, {}).get("file", {}))):
						#found process transition form "source" to "target" via entrypoint "succ"
						results.add((source, target, succ))
						transitions.add((source, target))

	suspicious = set()
	for source,target,trans in results:
		if ("write" in G.get_edge_data(source,trans, {}).get("file", {})):
			suspicious.add((source,target,trans))

	#print("\n".join([str(x) for x in suspicious]))
	return results, suspicious


def find_type_transition_execution(G):
	#get process transition edges
	process_transitions = defaultdict(set)
	#old networkx version !!!
	#for (u, v, data) in G.edges_iter(data="process"):
	for (u, v, data) in G.edges_iter(data=True):
		#print(u, " ", v, " ",data)
		if ("transition" in data.get("process", {})):
			process_transitions[v].add(u)

	results = set()
	transitions = set()
	
	execute_perms = set(["execute", "read", "getattr"])
	for target,sources in process_transitions.items():
		#find "entrypoint" in target node successors
		for succ in G.successors_iter(target):
			if ("entrypoint" in G.get_edge_data(target, succ, {}).get("file", {})):
				#test if sources have "execute" permissions on entrypoint
				for source in sources:
					if(execute_perms.issubset(G.get_edge_data(source, succ, {}).get("file", {}))):
						#found process transition form "source" to "target" via entrypoint "succ"
						results.add((source, target, succ))
						transitions.add((source, target))
	#TODO > test this on ungroupped data !!!!!!!!!!!!

	#print(process_transitions)
	#print("\n".join([str(x) for x in results]))
	'''
	print(sum([len(value) for value in process_transitions.values()]) , " > ", len(results))
	transition = None
	for target,sources in process_transitions.items():
		transition = (target, sources)
		break
	print("TROLO")
	print(transition)
	for (source, target, entry) in results:
		if source == [x for x in transition[1]][0] and target == transition[0]:
			print(source, ", ", target, ", ", entry)
	'''
	suspicious = set()
	for source,target,entry in results:
		if ("write" in G.get_edge_data(source,entry, {}).get("file", {})):
			suspicious.add((source,target,entry))

	#print("\n".join([str(x) for x in suspicious]))

	return results, transitions

# For a dynamic transition (from A to B) to happen, the following has to be allowed
# allow A B:process { dyntransition }; //transition is allowed to happen
# allow A self:process { setcurrent }; //execution of the transition
def find_dyntransitions_from(G, source):
	results = set()
	
	for succ in G.successors_iter(source):
		if "dyntransition" in (G.get_edge_data(source, succ, {}).get("process", {})) and
			"setcurrent" in (G.get_edge_data(source, source, {}).get("process", {})):
			results.add(succ)

	return results

# For a dynamic transition (from A to B) to happen, the following has to be allowed
# allow A B:process { dyntransition }; //transition is allowed to happen
# allow A self:process { setcurrent }; //execution of the transition
def find_all_dyntransitions(G):
	results = defaultdict(set)
	
	for (u, v, data) in G.edges_iter(data=True):
		if dyntransition_perms.issubset(data.get("process", {})) and
			"setcurrent" in (G.get_edge_data(u, u, {}).get("process", {})):
			results[u].add(v)

	return results

# Find entrypoint 
#def find_entrypoint_editing 

# find domain types that can be executed by someone 
# Types with attribute "domain" that are targets of "allow execute" rule
#def find_executable_domain_type(G):
#	pass

#find entrypoints that can be written by someone (and corresponding domains to which these entrypoints lead)
def find_writable_executables(G):
	# will contain entrypoint labels as keys
	# and sets of domains in which the process (spawned from given entrypoint) will run as values
	execs = defaultdict(set)
	#old networkx version !!!
	#for (u, v, data) in G.edges_iter(data="process"):
	execute_no_trans = set(["execute_no_trans", "read", "getattr"])
	for (u, v, data) in G.edges_iter(data=True):
		fileperms = data.get("file", {}))
		if ("entrypoint" in fileperms) or 
			(execute_no_trans.issubset(fileperms): #domain "u" can execute given file without transition
			execs[v].add(u)

	writable = defaultdict(set)
	for key,value in execs.items():
		#iterate over incomming edges of key (entrypoint)
		for (u,v,data) in G.in_edges_iter([key],data=True):
			if ("write" in data.get("file", {})):
				writable[key].add(u)
	#TODO return keys from writable - values will be from both writable and execs

	return execs