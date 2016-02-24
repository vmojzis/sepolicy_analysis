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


perm_sets = [
	("MANAGE", {"create", "open", "getattr", "setattr", "read", "write", "append", "rename", "link", "unlink", "ioctl", "lock"}),
	("RW", {"open", "getattr", "read", "write", "append", "ioctl", "lock"}),
	("RW_INH", {"getattr", "read", "write", "append", "ioctl", "lock"}),
	("WRITE", {"open", "getattr", "write", "append", "lock", "ioctl"}),
	("WRITE_INH", {"getattr", "write", "append", "lock", "ioctl"}),
	("READ", {"open", "getattr", "read", "ioctl", "lock"}),
	("READ_INH", {"getattr", "read", "ioctl", "lock"}),
	("CREATE", {"getattr", "create", "open"}),
	("EXEC", {"getattr", "open", "read", "execute", "ioctl", "execute_no_trans"}),
	("SIGNAL", {"sigchld", "sigkill", "sigstop", "signull", "signal"})]

#perm_sets_hierarchy = {
#	["MANAGE", "RW", "RW_INH", "WRITE", "WRITE_INH", "READ", "READ_INH"],
#	["MANAGE", "EXEC"]
#	["MANAGE", "CREATE"]
#	}

# creates a dictionary of permission sets contained in each permission set
# {perm_set:[smaller_perm_sets]}
def perm_sets_hierarchy():
	hierarchy = defaultdict(set)

	for (name,perm_list) in perm_sets:
		for (name2,perm_list2) in perm_sets:
			if name != name2 and perm_list2.issubset(perm_list):
				hierarchy[name].add(name2)
	return hierarchy

def print_permission_sets():
	print "\nCapitalised words in edge labels are permission sets containing the following permissions:\n"
	for label, perm_list in perm_sets:
		print label + ": " + ", ".join(sorted(perm_list))


def process_edge_labels(labels):
	hierarchy = perm_sets_hierarchy()
	#print(perm_sets)
	for edge in labels:
		label = set(labels[edge])
		to_remove = set()
		new_label = set()
		for (name,perm_list) in perm_sets:
			if perm_list.issubset(label):
				new_label.add(name)
				to_remove |= perm_list # union
				#label = label - perm_list
				#label.add(name)

				#print("DIFF> ", diff(label, perm_list))
		#remove redundant permission sets from new_label
		l_copy = [x for x in new_label]
		for item in l_copy:
			new_label -= hierarchy[item]

		del l_copy

		labels[edge] = ", ".join(new_label | (label - to_remove))
	return labels


'''
def process_edge_labels(labels):
	#print(perm_sets)
	for edge in labels:
		label = set(labels[edge])
		for (name,perm_list) in perm_sets:
			if perm_list.issubset(label):
				label = label - perm_list
				label.add(name)

				#print("DIFF> ", diff(label, perm_list))
		labels[edge] = ", ".join(label)
'''

