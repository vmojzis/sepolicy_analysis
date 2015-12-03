#!/usr/bin/env python

#egg_path='/home/vmojzis/DEVEL/selinux-policy/sepolicy_analysis/networkx-1.10-py3.4.egg'

#sys.path.append(egg_path)
import networkx as nx
import matplotlib.pyplot as plt

import selinux
import sepolicy   


# ?all? allow rules
#sepolicy.search(['allow'])

#all types
#sepolicy.info(0)
#print sepolicy.info(sepolicy.TYPE)

#get all entrypoints
#sepolicy.info(sepolicy.ATTRIBUTE, "entry_type")

#for domain_type in self.ptypes:
#            self.attributes[domain_type] = sepolicy.info(sepolicy.TYPE, ("%s") % domain_type)[0]["attributes"]

G = nx.DiGraph()

G.add_nodes_from([1,2,3])
G.add_edges_from([(1,2),(1,3)])

print G
#nx.draw(G)
#nx.draw_random(G)
nx.draw_circular(G,arrows=True, with_labels=True)
#nx.draw_spectral(G)
plt.show()
#plt.savefig("path.png")
#nx.draw_graphviz(G)
#nx.write_dot(G,'file.dot')

#export grahp to "trolo"
#nx.write_graphml(G, "trolo")