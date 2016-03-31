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
import domain_grouping as grouping

from collections import defaultdict

#filter out rules with non-domain source type (type without "domain" attribute)
def filter_non_domain(rules, domain_types_str):
	results = []
	for rule in rules:
		if data.is_attribute(rule.source) or str(rule.source) in domain_types_str:
			results.append(rule)
	return results


q = setools.TERuleQuery(setools.SELinuxPolicy(),ruletype=["allow"], tclass=["file", "process"])#, tclass=["file", "process"]) #, perms=["execute"]
rules = q.results()
rules = [x for x in rules]

rules = data.filter_terules_boolean(rules)


domain_types = data.get_domain_types()
domain_types_str = set([str(x) for x in domain_types])
print("expanding")
rules = data.expand_rules(rules)
print("filtering")
rules = filter_non_domain(rules, domain_types_str)


print("matrix")
G = nx.DiGraph()

matrix = defaultdict(set)

#domain grouping
if True:
	domain_grouping = grouping.group_types_cil()
	#reversal of domain grouping - for fast inverse search
	reverse_grouping = {}
	for group in domain_grouping.values():
		for _type in group.types:
			reverse_grouping[_type] = group

	for rule in rules:
		source = str(rule.source).lower()
		#domain grouping
		source = reverse_grouping.get(source, None)
		target = str(rule.target).lower()
		target = reverse_grouping.get(target, None)
		if source == None:
			print("Failed to find group for: ", str(rule.source).lower())
		if target == None:
			print("Failed to find group for: ", str(rule.target).lower())
		matrix[(source, target, str(rule.tclass))] |= set(rule.perms)
else:
	for rule in rules:
		matrix[(str(rule.source).lower(), str(rule.target).lower(), str(rule.tclass).lower())] |= set(rule.perms)

print("edges")

edges = [(key[0],key[1],{key[2]:value}) for key,value in matrix.items()]
#print("\n".join([str(x) for x in edges]))
print("graph")
G.add_edges_from(edges)
#rule.tclass

file = open('data/rules_dump.bin','wb')
print("writing")
pickle.dump(G, file)
file.close()


#G[1][3]['color']='blue'

#rules = set([str(x) for x in rules])
#print("\n".join(rules))
#domain_types = [x for x in domain_types]
#print(domain_types)
#print(type(domain_types[0]))

'''
for rule in rules:
	if (not data.is_attribute(rule.source)) and (str(rule.source) not in domain_types):
		print(rule)
'''

max_ = 0
maxtype = "NOT_FOUND"



#print("\n".join([str(x) for x in rules if data.is_attribute(x.source)]))


'''
print("starting main cycle")
for type_ in types:
	#attrs = data.get_attributes_of(type_)
	#attrs.append(type_)
	#attrs = set(attrs)

	cnt = 0
	print("new type: ", type_)
	for rule in rules:
		if rule.source == type_:
			cnt += 1

	if cnt > max_:
		max_ = cnt
		maxtype = type_
		print("New max>>>>> ", max_)

print(maxtype, " > ", max_)
'''
'''
counts = {}
for rule in rules:
	if str(rule.source) in counts:
		counts[str(rule.source)] += 1
	else:
		counts[str(rule.source)] = 1

max_ = 0
maxtype = "NOTHING"
for key,value in counts.items():
	if value > max_:
		max_ = value
		maxtype = key
print(max_, " > ", maxtype)

print(sorted(counts.values()))
'''
#print(type(rules[0].target))


#rules = sepolicy.search([sepolicy.ALLOW],{})
#rules = set([str(x) for x in rules])
#rules = [x for x in rules]


#rules2 = sepolicy.search([sepolicy.ALLOW])
#rules2 = set([str(x) for x in rules])

#for rule in rules:
#	for rule2 in rules2:
#		pass


#print(len(rules), " vs. ", len(rules2))

#print("\n".join([str(x) for x in rules2]))
#print(rules2[0])
#print("\n".join([str(x) for x in rules]))



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