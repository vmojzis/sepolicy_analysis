#!/usr/bin/env python3
import selinux
import sepolicy  

import pickle
import networkx as nx
import sys

import policy_data_collection as data
import evaluation_functions as evaluation
import graph_query_functions as functions
import argparse
import domain_grouping as grouping
from collections import defaultdict

def is_iterable(obj):
	try:
		iterator = iter(obj)
		return True
	except TypeError as te:
		return False

#get function pointer (from "graph_query_functions" module) to given query function
def get_query_function(name):
	try:
		function = getattr(functions, name + "_query")
		
		return function

	except AttributeError as e:
		return None

#get function pointer to "string" function (from "graph_query_functions" module)
def get_string_function(name):
	try:
		function = getattr(functions, name + "_string")
		
		return function

	except AttributeError as e:
		return None

#get function pointer to "diff" function (from "graph_query_functions" module)
def get_diff_function(name):
	try:
		function = getattr(functions, name + "_diff")
		
		return function

	except AttributeError as e:
		return None


#load networkx graph from given file
def get_graph(filename):
	try:
		file = open(filename, 'rb')
		G = pickle.load(file)
		file.close()
		
		return G

	except IOError as e:
		print("Failed to open graph file.\nI/O error({0}): {1}".format(e.errno, e.strerror), file=sys.stderr)
		sys.exit()

#return string representation of given results
def results_str(results, f_name):
	# try to find user definde function
	function = get_string_function(f_name)
	if function:
		return function(results)
	else:
		if not results:
			return ""
		# dictionary of results
		if isinstance(results, dict):
			return "\t" + "\n\t".join([item_str(x) + "\n\t\t" + item_str(y) for x,y in sorted(results.items())])
		
		return "\t" + "\n\t".join([item_str(x) for x in sorted(results)])

# item2 will be considered a baseline 
# returns results in "item1" that are not in "item2"
def diff(item1, item2):
	#print("\n".join([str(x) for x in sorted(item2)]))
	function = get_diff_function(f_name)
	if function:
		return function(item1, item2)
	else:
		#dictionaries of sets - defaultdict(set)
		if isinstance(item1, defaultdict):
			results = defaultdict(set)
			for key,value in item1.items():
				val = value - item2.get(key, set())
				if val:
					results[key] = val
			return results

		return set(item1) - set(item2)

def item_str(item):
	# item is list or set
	if (isinstance(item, list) or isinstance(item, tuple) or isinstance(item, set)):
		return ", ".join([str(x) for x in item])
	else:
		return str(item)


parser = argparse.ArgumentParser(description='SELinux policy analysis tool - graph query.')

parser.add_argument("filename", help="Policy graph file.")

parser.add_argument("query_functions", help="Comma separated list of query functions to be executed.")

parser.add_argument("-d", "--diff", metavar="FILENAME2", dest="diff_filename",
                  help="Another policy graph file.")

args = parser.parse_args()

G = get_graph(args.filename)

# query function pointers
query_functions = []
# split list attributes
if args.query_functions:
	args.query_functions = [x.strip() for x in args.query_functions.split(",")]
	for f_name in args.query_functions:
		fun = get_query_function(f_name)
		if fun:
			query_functions.append(fun)
		else:
			print("Failed to find query function: " + f_name + "! Skipping." ,file=sys.stderr)
			args.query_functions.remove(f_name)

results = []
for fun in query_functions:
	results.append(fun(G))

if args.diff_filename:
	results2 = []
	dif = []
	G2 = get_graph(args.diff_filename)

	for fun in query_functions:
		results2.append(fun(G2))

	for i in range(len(results)):
		dif.append(diff(results[i], results2[i]))


	results = dif

#print(results)
for i in range(len(results)):
	#print function name followed by results
	print(args.query_functions[i] + ":")
	print(results_str(results[i], args.query_functions[i]))

#builder.build_graph(args.policy, args.domain_grouping, args.filename, args.classes, args.filter_bools)

#methodToCall = getattr(evaluation, 'bar')r
#result = methodToCall()

'''

file = open(args.filename, 'rb')
G_g = pickle.load(file)
file.close()

file = open('data/rules_file_process.bin', 'rb')
G = pickle.load(file)
file.close()
'''
#print("Edges> ", len(G.edges()), " nodes> ", len(G.nodes()))
#print(G.edges(data=True)[0])
#print(str(G.edges(data=True)[0][0]))
#print(str(G.edges(data=True)[0][1]))
'''for edge in G.edges(data=True):
	if edge[0] != edge[1] and edge[2].get("process") != None:
		print(edge)
		break
'''

#results, transitions = evaluation.find_type_transition_execution(G_g)
'''
for a,b,c in results:
	if (str(a) == "accountsd") and (str(b) == "abrt") and (str(c) == "abrt"):
		print("YEAH")
		print(a.domains, "\n" ,b.domains, "\n" , c.types)
		print(G_g.get_edge_data(a,b))
		print(G_g.get_edge_data(b,c))
		print(G_g.get_edge_data(a,c))
'''
#results2, suspicious = evaluation.expand_type_transition_execution(G,transitions)
#print(results-results2)
#suspicious_p = defaultdict(set)
#for a,b,c in suspicious:
#	suspicious_p[(a,b)].add(c)
#print("\n\n".join([str(x)+" > " + ", ".join(y) for x,y in suspicious_p.items() if len(y) > 5]))
#sus pmes= set()
#for key, value in suspicious_p.items():
#	if len(value) > 5:
#		susp.add(key)

#print("\n".join([str(x) for x in susp]))