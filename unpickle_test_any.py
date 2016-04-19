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



file = open('data/rules_grouping_file_process.bin', 'rb')
G_g = pickle.load(file)
file.close()

file = open('data/rules_file_process.bin', 'rb')
G = pickle.load(file)
file.close()

#print("Edges> ", len(G.edges()), " nodes> ", len(G.nodes()))
#print(G.edges(data=True)[0])
#print(str(G.edges(data=True)[0][0]))
#print(str(G.edges(data=True)[0][1]))
'''for edge in G.edges(data=True):
	if edge[0] != edge[1] and edge[2].get("process") != None:
		print(edge)
		break
'''
#########################################
domain_grouping = grouping.group_types_cil()
#reversal of domain grouping - for fast inverse search
reverse_grouping = {}
for group in domain_grouping.values():
	for _type in group.types:
		reverse_grouping[_type] = group
###########################################
results_groupped = set()
results = evaluation.find_type_transition_execution(G)
#for a,b,c in results:
#	results_groupped.add((reverse_grouping[a], reverse_grouping[b], reverse_grouping[c]))

#results2, transitions = evaluation.find_type_transition_execution(G_g)

#print("\n".join([str(x) for x in (results)]))

#print(results_groupped)
results2 = evaluation.find_type_transition_execution_uing_groups(G,G_g)

print("\n".join([str(x) for x in (results2-results)]))

#print(results-results2)
#print("\n".join([str(x) for x in results2]))
#print(results2)