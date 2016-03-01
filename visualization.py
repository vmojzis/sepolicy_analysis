#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
#egg_path='/home/vmojzis/DEVEL/selinux-policy/sepolicy_analysis/networkx-1.10-py3.4.egg'

#sys.path.append(egg_path)
import networkx as nx
import matplotlib.pyplot as plt

import selinux
import sepolicy   
import random
import copy
import matplotlib.pyplot as plt
import matplotlib.cm as cmx
import matplotlib.colors as colors
from collections import defaultdict
from edge_labels_optimizer import process_edge_labels, print_permission_sets

import policy_data_collection as data
import config_loading as config
import math

# map the integer indices 0, 1, ... N-1 to distinct RGB colors
def get_cmap(N):
    '''Returns a function that maps each index in 0, 1, ... N-1 to a distinct 
    RGB color.'''
    color_norm  = colors.Normalize(vmin=0, vmax=N)
    scalar_map = cmx.ScalarMappable(norm=color_norm, cmap='hsv') 
    def map_index_to_rgb_color(index):
        return scalar_map.to_rgba(index)
    return map_index_to_rgb_color


'''
def foo_():
	#me = 'init_t'
	#me = 'mozilla_plugin_t'
	me = 'rdisc_t'
	#me = 'sshd_t'
	# ?all? allow rules #print sepolicy.search(['allow']) rules =
	#rules_out = sepolicy.search([sepolicy.ALLOW], {'source': me, 'permlist': ['write'], 'class': 'file'}) 
	#rules_in = sepolicy.search([sepolicy.ALLOW], {'target': me, 'class': 'file'}) 
	rules_out = sepolicy.search([sepolicy.ALLOW], {'source': me, 'class': 'file'}) 
	rules_in = []

	my_attributes = sepolicy.info(sepolicy.TYPE, me)[0]["attributes"]

	targets = [me]

	for i in rules_out:
		if i['target'] not in targets:
			targets.append(i['target'])
	
	print(targets)


	# Add edges to output graph
	# Attributes of source type have to be considered as exceptions 
	# rules such as "attribute -> type" have to be converted to "source_type -> type"
	#edges = []
	edge_labels = defaultdict(list)

	# dictionary containing sets of edges corresponding to each attribute
	# attribute_edges['attribute'] = [edges_corresponding_to_attribute]
	attribute_edges = {}
	#for attr in my_attributes:
	#	attribute_edges[attr] = []

	for i in rules_in:
		if i['source'] == me:
			continue # skip loops (edge form vertex to itself)
		target = i['target']
		if target in my_attributes:
			target = me
			if(i['target'] in attribute_edges):
				attribute_edges[i['target']].append((i['source'], target))
			else:
				attribute_edges[i['target']] = [(i['source'], target)]

		edge_labels[(i['source'], target)].extend(i['permlist'])

	for i in rules_out:
		if i['target'] == me:
			continue # skip loops (edge form vertex to itself)
		source = i['source']
		if source in my_attributes:
			source = me
			if(i['source'] in attribute_edges):
				attribute_edges[i['source']].append((source, i['target']))
			else:
				attribute_edges[i['source']] = [(source, i['target'])]
		
		edge_labels[(source, i['target'])].extend(i['permlist'])

	process_edge_labels(edge_labels)

	make_graph(edge_labels, attribute_edges, me)

def foo():
	me = 'rdisc_t'

	rules = data.get_type_enf_rules(_ruletype = ["allow"], _source = me, _tclass = ['file'])
	rules = data.filter_terules_boolean(rules, config.get_boolean_config())
	edge_labels = defaultdict(list)

	my_attributes = data.get_attributes_of(me)
	# dictionary containing sets of edges corresponding to each attribute
	# attribute_edges['attribute'] = [edges_corresponding_to_attribute]
	attribute_edges = {}
	#for attr in my_attributes:
	#	attribute_edges[attr] = []

	filtered_attributes = set(['domain', 'daemon'])

	dotted_edges = set()

	for i in rules:
		target_type = i.target
		if str(target_type) == me:
			continue # skip loops (edge form vertex to itself)
		source = str(i.source)

		#skip filtered attributes
		if source in filtered_attributes:
			continue

		if source in my_attributes:
			source = me
			if(str(i.source) in attribute_edges):
				attribute_edges[str(i.source)].append((source, str(i.target)))
			else:
				attribute_edges[str(i.source)] = [(source, str(i.target))]

		edge_labels[(source, str(i.target))].extend([str(x) for x in i.perms])


		if data.is_conditional(i):
			dotted_edges.add((source, str(i.target)))

	process_edge_labels(edge_labels)

	
	make_graph(edge_labels, attribute_edges, dotted_edges, me)
'''

# query - argparser output
#TODO - specify the query and write command line argument reading
def apply_query(query):
					   
	rules = data.get_type_enf_rules(_ruletype = ["allow"],
								    _source = query.source,
								    _target = query.target, 
								    _tclass = query.tclass,
									_perms = query.perms,
									_booleans = query.boolean
								    )

	# filtering

	if query.filter_bools != None:
		rules = data.filter_terules_boolean(rules, query.filter_bools)

	#attribute containing "main domain"
	main_domain = "source" if query.source else "target"

	# filter attribute rules
	filtered_rules = []
	if query.filter_attrs:
		for rule in rules:
			attr = str(getattr(rule, main_domain))

			#skip filtered attributes
			if attr in query.filter_attrs:
				continue
			filtered_rules.append(rule)

	
	# expand rules ending in attribute
	if True:
		rules = []
		other_side = "source" if main_domain == "target" else "target"
		attributes = data.get_attributes
		for rule in filtered_rules:
			if data.is_attribute(getattr(rule, other_side)):
				rules.extend(data.half_expand_rule(rule, main_domain == "target"))
			else:
				rules.append(rule)
		#apply_domain_grouping()

	else:
		rules = filtered_rules	


	visualise_rules(query.main_domain, bool(query.source), rules)

#main_domain - string (source/destination of given rules)
#is_source - True if main_domain (and it's attributes) is source of given rules
#rules - array of [AVRule|TERule|ExpandedAVRule|ExpandedTERule]
def visualise_rules(main_domain, is_source, rules):
	
	my_attributes = data.get_attributes_of(main_domain)
	# dictionary containing sets of edges corresponding to each attribute
	# attribute_edges['attribute'] = [edges_corresponding_to_attribute]
	attribute_edges = defaultdict(list)

	#edges corresponding to boolean-conditioned rules
	conditional_edges = set() 

	edge_labels = defaultdict(list)

	#booleans and edges they controll
	booleans = defaultdict(set)

	#TODO skip loops (edge form vertex to itself)
	for i in rules:
		source = str(i.source)
		target = str(i.target)

		if is_source:
			#change source to "main_domain" if it is an attribute
			if source in my_attributes:
				attribute_edges[source].append((main_domain, target))
				source = main_domain
		else:
			#change target to "main_domain" if it is an attribute
			if target in my_attributes:
				attribute_edges[target].append((source, main_domain))
				target = main_domain

		edge_labels[(source, target)].extend([str(x) for x in i.perms])

		if data.is_conditional(i):
			booleans[data.is_conditional(i)].add(target if is_source else source)
			conditional_edges.add((source, target))
	
	#print booleans
	print("Boolean conditioned edges:\n")
	for key,value in booleans.items():
		print(key+":")
		for t in value:
			print("\t",t)

	process_edge_labels(edge_labels)

	#remove self loops
	edge_labels.pop((main_domain, main_domain), None)

	make_graph(edge_labels, attribute_edges, conditional_edges, main_domain)
# edges -> dictionary {(pair_of_nodes):label}
# colored_edges -> dictionary {group_name:[group_edges]}
def make_graph(edges, colored_edges, dotted_edges, me):
	G = nx.DiGraph()
	#for (x,y) in edges.keys():
	#	print(x + " - " + y)

	G.add_edges_from(edges.keys()) # nodes are added with keys - no unconnected edges

	# generate circular layout using graph without main node (which will be in the center)
	G2 = nx.DiGraph()
	G2.add_nodes_from(G.node)
	G2.remove_node(me)
	pos=nx.circular_layout(G2)
	del(G2)
	
	pos[me] = [0.5,0.5]

	#######################
	# customized graph drawing

	# set canvas size
	figsize = len(edges) if len(edges) > 30 else 30
	if figsize > 400:
		figsize = 400
		print("\nMaximum canvas size exceeded, the graph may not scale properly!\n")

	plt.figure(figsize=(figsize,figsize/2))
	

	nx.draw_networkx_nodes(G,pos,
	                       node_color='w',
	                   	   alpha=1)
	# edges

	# colored edges
	colormap = get_cmap(len(colored_edges.keys()))
	colorcount = 0
	edge_colors = []
	# edge colors -- corresponding to each attribute
	for key in colored_edges.keys():
		col = colormap(colorcount)
		edge_colors.append(col)
		colorcount += 1
		nx.draw_networkx_edges(G,pos, colored_edges[key],
	                       width=3,alpha=0.5,edge_color=colors.rgb2hex(col))

	solid_edges = set(G.edges())-dotted_edges
	
	nx.draw_networkx_edges(G,pos,solid_edges, edge_color = "grey", width=1.0,alpha=1)
	nx.draw_networkx_edges(G,pos,dotted_edges, edge_color = "grey", style = "dashed",width=1.0,alpha=1)

	nx.draw_networkx_edge_labels(G,pos, edge_labels = edges, clip_on = True, label_pos=0.5, font_size=13)
	pos2 = {}
	for vector in G.node:
		pos2[vector] = [pos[vector][0], pos[vector][1]+ 1.0/figsize]

	nx.draw_networkx_labels(G,pos2,font_size=16)

	#add legend for attributes - each attribute gets a node
	#------------------------------
	edges_legend = [x.upper() for x in colored_edges.keys()]

	G.add_nodes_from(edges_legend)

	#2.5 in graph coordinates is width of the whole graph
	if len(edges_legend) < 2:
		x_pos = 0.5
		_delta = 0
	else:
		_delta = 1/(len(edges_legend)-1)
		x_pos = 0
	for attr in edges_legend:
		pos2[attr.upper()] = [x_pos,-0.1+1.0/figsize]
		pos[attr.upper()] = [x_pos,-0.1]
		x_pos += _delta
	
	#permission sets legend
	#print("\n\n\n")
	print_permission_sets()

	nx.draw_networkx_labels(G, pos2, nodelist = edges_legend, font_size=16)
	nx.draw_networkx_nodes(G, pos, nodelist = edges_legend, node_color = edge_colors)
	#------------------------------

	plt.savefig("path.pdf", format='pdf', dpi=500)
	#plt.show()
	#nx.draw_graphviz(G)
	#nx.write_dot(G,'file.dot')

	#export grahp to "trolo"
	#nx.write_graphml(G, "trolo")



