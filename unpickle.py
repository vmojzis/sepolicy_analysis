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

from collections import defaultdict



file = open('rules_dump.bin', 'rb')
G = pickle.load(file)
file.close()
print("Edges> ", len(G.edges()), " nodes> ", len(G.nodes()))
#print(G.edges(data=True)[0])
#print(str(G.edges(data=True)[0][0]))
#print(str(G.edges(data=True)[0][1]))
for edge in G.edges(data=True):
	if edge[0] != edge[1] and edge[2].get("process") != None:
		print(edge)
		break


evaluation.find_type_transition_execution(G)
#print("\n".join([str(x) for x in G.edges(data=True)]))