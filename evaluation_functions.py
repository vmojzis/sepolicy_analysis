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



def find_type_transition_execution(G):
	#get process transition edges
	process_transitions = defaultdict(set)
	#old networkx version !!!
	#for (u, v, data) in G.edges_iter(data="process"):
	for (u, v, data) in G.edges_iter(data=True):
		#print(u, " ", v, " ",data)
		if (u != v) and ("transition" in data.get("process", {})):
			process_transitions[v].add(u)

	results = set()
	transitions = set()
	execute_perms = set(["execute", "read", "open", "getattr"])
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
	for source,target in transitions:
		if ("write" in G.get_edge_data(source,target, {}).get("file", {})):
			suspicious.add((source,target))

	print("\n".join([str(x) for x in suspicious]))