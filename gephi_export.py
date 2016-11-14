#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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


#package - domain group object corresponding to given package
#is_source - True if main_domain (and it's attributes) is source of given rules
#rules - array of [AVRule|TERule|ExpandedAVRule|ExpandedTERule]
def export_package(package, package_attributes ,rules):
	edge_labels = defaultdict(list) #edges with permissions
	attribute_edges_dict = defaultdict(list) #special edges connecting attributes and corresponding types

	nodes = set()

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
				nodes.add(s)
				nodes.add(t)


	process_edge_labels(edge_labels)

	G = nx.DiGraph()

	#[(key[0],key[1],{key[2]:value}) for key,value in matrix.items()]
	G.add_nodes_from([(n,{"weight":(2 if n in package_types else 1), "type":("attribute" if n in attribute_nodes else "selected" if n in package_types else "type")}) for n in nodes])
	G.add_edges_from([(key[0],key[1],{"label":val}) for key,val in edge_labels.items()]) # nodes are added with keys - no unconnected edges
	attribute_edges = set()	
	for attr, val in attribute_edges_dict.items():
		for t in val:
			attribute_edges.add((attr, t))

	G.add_edges_from([(v,u,{"type":"typeattr"}) for (u,v) in attribute_edges]) # nodes are added with keys - no unconnected edges
	
	nx.write_graphml(G, str(package) + ".graphml")
	