#!/usr/bin/env python3

#egg_path='/home/vmojzis/DEVEL/selinux-policy/sepolicy_analysis/networkx-1.10-py3.4.egg'

#sys.path.append(egg_path)
import networkx as nx
import matplotlib.pyplot as plt

import selinux
import sepolicy   


G = nx.DiGraph()

all_types = sepolicy.info(sepolicy.TYPE)
#"name"

rules = sepolicy.search([sepolicy.ALLOW],{})

print("\n".join([str(x) for x in rules]))

'''
me = 'init_t'
# ?all? allow rules #print sepolicy.search(['allow']) rules =
rules = sepolicy.search([sepolicy.ALLOW], {'source': me, 'permlist': ['write'], 'class': 'file'}) 
rules += sepolicy.search([sepolicy.ALLOW], {'target': me, 'permlist': ['write'], 'class': 'file'}) 

my_attributes = sepolicy.info(sepolicy.TYPE, me)[0]["attributes"]


#print rules #all types #sepolicy.info(0) #print
#sepolicy.info(sepolicy.TYPE)
print(my_attributes)

targets = [me]

for i in rules:
	if i['target'] not in targets:
		targets.append(i['target'])
print(targets)

for i in rules:
	if i['target'] not in targets:
		targets.append(i['target'])

edges = []

for i in rules:
	source = i['source']
	target = i['target']
	if i['source'] in my_attributes:
		source = me
	if i['target'] in my_attributes:
		target = me
	
	edges.append((source, target))

print(edges)

#get all entrypoints
#sepolicy.info(sepolicy.ATTRIBUTE, "entry_type")

#for domain_type in self.ptypes:
#            self.attributes[domain_type] = sepolicy.info(sepolicy.TYPE, ("%s") % domain_type)[0]["attributes"]


G.add_nodes_from(targets)
G.add_edges_from(edges)

print(G)
#nx.draw(G)
#nx.draw_random(G)


nx.draw_circular(G,arrows=True, with_labels=True, node_color='r',
                       node_size=500,
                   alpha=0.8)
#nx.draw_spectral(G)
plt.show()
#plt.savefig("path.png")
#nx.draw_graphviz(G)
#nx.write_dot(G,'file.dot')

#export grahp to "trolo"
#nx.write_graphml(G, "trolo")'''