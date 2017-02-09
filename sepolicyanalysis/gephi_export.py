# (C) Copyright 2016 Vit Mojzis, vmojzis@redhat.com
# 
# This program is distributed under the terms of the GNU General Public License
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import networkx as nx
import selinux
import sepolicy   
import random
import copy
import matplotlib.pyplot as plt
import matplotlib.cm as cmx
import matplotlib.colors as colors
from collections import defaultdict

from sepolicyanalysis.edge_labels_optimizer import process_edge_labels, print_permission_sets
import sepolicyanalysis.policy_data_collection as data
import sepolicyanalysis.config_loading as config

import math


#package - domain group object corresponding to given package
#is_source - True if main_domain (and it's attributes) is source of given rules
#rules - array of [AVRule|TERule|ExpandedAVRule|ExpandedTERule]
def export_package(package, package_attributes ,rules):
	edge_labels = defaultdict(list) #edges with permissions
	attribute_edges_dict = defaultdict(list) #special edges connecting attributes and corresponding types

	package_types = set(package.types)
		
	attribute_nodes = set() # should be assigned special attribute so that gephi recognises them

	for rule in rules:
		source = str(rule.source)
		target = str(rule.target)
		sources = set([source]) #expanded from attributes
		targets = set([target])

		if data.is_attribute(rule.source):
			attribute_nodes.add(source)
			if (source in package_attributes):
				#sources = set(data.get_types_of(rule.source)) & package_types
				attribute_edges_dict[source].extend(set(data.get_types_of(rule.source)) & package_types)
				pass
			else:
				attribute_nodes.add(source)

		if data.is_attribute(rule.target):
			attribute_nodes.add(target)
			if (target in package_attributes):
				#targets = set(data.get_types_of(rule.target)) & package_types
				attribute_edges_dict[target].extend(set(data.get_types_of(rule.target)) & package_types)
				pass
			else:
				attribute_nodes.add(target)
		# generate edges for the final graph
		for s in sources:
			for t in targets:
				edge_labels[(s, t)].extend([str(x) for x in rule.perms])

	process_edge_labels(edge_labels)

	G = nx.DiGraph()

	# Add special attributes for Gephi (color, type, ...)

	G.add_edges_from([(key[0],key[1],{"label":val, "color":"cyan"}) for key,val in edge_labels.items()])

	attribute_edges = set()	
	for attr, val in attribute_edges_dict.items():
		for t in val:
			attribute_edges.add((attr, t))

	G.add_edges_from([(v,u,{"type":"typeattr", "color":"redorange"}) for (u,v) in attribute_edges])

	#assign color to each node (attribute vs type from selected package vs other type)
	nodes_gephi = []
	for n in G.nodes():
		nodetype = "type"
		nodecolor = "cyan"#"skyblue turquoise"
		if n in attribute_nodes:
			nodetype = "attribute"
			nodecolor = "darkorange"
		elif n in package_types:
			nodetype = "selected"
			nodecolor = "green"
		nodes_gephi.append((n,{"type":nodetype, "color":nodecolor}))

#		nodecolor = (0,197,255)
#		if n in attribute_nodes:
#			nodetype = "attribute"
#			nodecolor = (255,107,23)
#		elif n in package_types:
#			nodetype = "selected"
#			nodecolor = (1,231,0)
#		nodes_gephi.append((n,{"label":n,"type":nodetype, "r":nodecolor[0], "g":nodecolor[1], "b":nodecolor[2]}))

	G.add_nodes_from(nodes_gephi)

	#TODO: allow user to specify output file name
	nx.write_graphml(G, str(package) + ".graphml")
	