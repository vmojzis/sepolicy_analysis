#!/usr/bin/env python3
import selinux
import sepolicy  

import pickle
import networkx as nx

import policy_data_collection as data
import evaluation_functions as evaluation
import argparse
import domain_grouping as grouping


parser = argparse.ArgumentParser(description='SELinux policy analysis tool - graph query.')

parser.add_argument("filename", help="Policy graph file.")

parser.add_argument("policy", help="Path to the SELinux policy to be used.", nargs="?")


args = parser.parse_args()

# split list attributes
if args.classes:
	args.classes = args.classes.split(",")

if args.filter_bools != None:
	args.filter_bools = builder.parse_bool_config(args.filter_bools)

builder.build_graph(args.policy, args.domain_grouping, args.filename, args.classes, args.filter_bools)



methodToCall = getattr(evaluation, 'bar')
result = methodToCall()









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

results, transitions = evaluation.find_type_transition_execution(G_g)
'''
for a,b,c in results:
	if (str(a) == "accountsd") and (str(b) == "abrt") and (str(c) == "abrt"):
		print("YEAH")
		print(a.domains, "\n" ,b.domains, "\n" , c.types)
		print(G_g.get_edge_data(a,b))
		print(G_g.get_edge_data(b,c))
		print(G_g.get_edge_data(a,c))
'''
results2, suspicious = evaluation.expand_type_transition_execution(G,transitions)
#print(results-results2)
suspicious_p = defaultdict(set)
for a,b,c in suspicious:
	suspicious_p[(a,b)].add(c)
#print("\n\n".join([str(x)+" > " + ", ".join(y) for x,y in suspicious_p.items() if len(y) > 5]))
sus pmes= set()
for key, value in suspicious_p.items():
#	if len(value) > 5:
		susp.add(key)

print("\n".join([str(x) for x in susp]))