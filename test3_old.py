#!/usr/bin/env python

#egg_path='/home/vmojzis/DEVEL/selinux-policy/sepolicy_analysis/networkx-1.10-py3.4.egg'

#sys.path.append(egg_path)
import networkx as nx
import matplotlib.pyplot as plt

import selinux
import sepolicy   
import random
import matplotlib.pyplot as plt
import matplotlib.cm as cmx
import matplotlib.colors as colors
from collections import defaultdict
from edge_labels_optimizer import process_edge_labels, print_permission_sets
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



G = nx.DiGraph()

#me = 'init_t'
#me = 'mozilla_plugin_t'
#me = 'sshd_t'
# ?all? allow rules #print sepolicy.search(['allow']) rules =
#rules_out = sepolicy.search([sepolicy.ALLOW], {'source': me, 'permlist': ['write'], 'class': 'file'}) 
#rules_in = sepolicy.search([sepolicy.ALLOW], {'target': me, 'permlist': ['write'], 'class': 'file'}) 
rules_out = sepolicy.search([sepolicy.ALLOW], {'source': me, 'class': 'file'}) 
rules_in = []

my_attributes = sepolicy.info(sepolicy.TYPE, me)[0]["attributes"]

print("Attributes>")
print(my_attributes)
print("\n\n\n")
#print rules #all types #sepolicy.info(0) #print
#sepolicy.info(sepolicy.TYPE)
#print my_attributes

targets = [me]

for i in rules_out:
	if i['target'] not in targets:
		targets.append(i['target'])

print(targets)


# Add edges to output graph
# Attributes of source type have to be considered as exceptions 
# rules such as "attribute -> type" have to be converted to "source_type -> type"
edges = []
edge_labels = defaultdict(list)

# dictionary containing sets of edges corresponding to each attribute
# attribute_edges['attribute'] = [edges_corresponding_to_attribute]
attribute_edges = {}
#for attr in my_attributes:
#	attribute_edges[attr] = []

for i in rules_in:
	target = i['target']
	if target in my_attributes:
		target = me
		if(i['target'] in attribute_edges):
			attribute_edges[i['target']].append((i['source'], target))
		else:
			attribute_edges[i['target']] = [(i['source'], target)]
	#else:
	#	attribute_edges['other'].append((i['source'], target))
	
	edges.append((i['source'], target))
	#if (i['source'], target) in edge_labels:
  	#	edge_labels[(i['source'], target)] += ", " + i['class']
	#else:
  	#	edge_labels[(i['source'], target)] = i['class']
	
	edge_labels[(i['source'], target)].extend(i['permlist'])

for i in rules_out:
	source = i['source']
	if source in my_attributes:
		source = me
		if(i['source'] in attribute_edges):
			attribute_edges[i['source']].append((source, i['target']))
		else:
			attribute_edges[i['source']] = [(source, i['target'])]

	#else:
	#	attribute_edges['other'].append((source, i['target']))
	
	edges.append((source, i['target']))

	#if (source, i['target']) in edge_labels:
  	#	edge_labels[(source, i['target'])] += ", " + i['class']
	#else:
  	#	edge_labels[(source, i['target'])] = i['class']
	
	edge_labels[(source, i['target'])].extend(i['permlist'])

print(edge_labels)
print("\n\n")
process_edge_labels(edge_labels)
print(edge_labels)
#print("\n\n")
#print(edges)

#get all entrypoints
#sepolicy.info(sepolicy.ATTRIBUTE, "entry_type")

#for domain_type in self.ptypes:
#            self.attributes[domain_type] = sepolicy.info(sepolicy.TYPE, ("%s") % domain_type)[0]["attributes"]


#G.add_nodes_from(targets)
G.add_edges_from(edges)

#print G
#nx.draw(G)
#nx.draw_random(G)
pos=nx.circular_layout(G)

pos[me] = [0,0]
# draw complete graph
#nx.draw_circular(G,arrows=True, with_labels=True, node_color='r',
#                       node_size=500,
#                   alpha=0.8)


#######################
# customized graph drawing
figsize = len(edges) #if len(edges) > 20 else 20
figsize= figsize 
#figsize = len(edges) if len(edges) > 20 else 20
plt.figure(figsize=(figsize,figsize/2))

nx.draw_networkx_nodes(G,pos,
#                       nodelist=[0,1,2,3],
                       node_color='w',
                       #node_size=500,
                   alpha=1)
#nx.draw_networkx_nodes(G,pos,
#                       node_color='b',
#                       node_size=500,
#                   alpha=0.8)

# edges
nx.draw_networkx_edges(G,pos,width=1.0,alpha=0.5)

colormap = get_cmap(len(attribute_edges.keys()))
colorcount = 0
edge_colors = []
# edge colors -- corresponding to each attribute

for key in attribute_edges.keys():
	col = colormap(colorcount)
	edge_colors.append(col)
	colorcount += 1
	print (col)
	nx.draw_networkx_edges(G,pos, attribute_edges[key],
                       width=2,alpha=0.5,edge_color=colors.rgb2hex(col))

#nx.draw_networkx_edges(G,pos,
#                       edgelist=[(0,1),(1,2),(2,3),(3,0)],
#                       width=8,alpha=0.5,edge_color='r')




# some math labels
#labels={}
#labels[0]=r'$a$'

nx.draw_networkx_edge_labels(G,pos, edge_labels = edge_labels, clip_on = True, label_pos=0.5, font_size=13)
pos2 = {}
for vector in G.node:
	pos2[vector] = [pos[vector][0], pos[vector][1]+ 2.0/figsize]

nx.draw_networkx_labels(G,pos2,font_size=16)

#add legend for attributes - each attribute gets a node
#------------------------------
edges_legend = [x.upper() for x in attribute_edges.keys()]

G.add_nodes_from(edges_legend)

#2.5 corresponds to graph coordinates - width of whole graph
_delta = 2.4/(len(edges_legend)-1)
x_pos = -1.2
for attr in edges_legend:
	pos2[attr.upper()] = [x_pos,-1.3+2.0/figsize]
	pos[attr.upper()] = [x_pos,-1.3]
	x_pos += _delta

print "\n\n\n"
print_permission_sets()


nx.draw_networkx_labels(G, pos2, nodelist = edges_legend, font_size=16)
nx.draw_networkx_nodes(G, pos, nodelist = edges_legend, node_color = edge_colors)
#------------------------------




plt.savefig("path.eps", format='eps', dpi=300)
#plt.show()
#nx.draw_graphviz(G)
#nx.write_dot(G,'file.dot')

#export grahp to "trolo"
#nx.write_graphml(G, "trolo")



