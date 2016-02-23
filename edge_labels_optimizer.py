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
("MANAGE", ["create", "open", "getattr", "setattr", "read", "write", "append", "rename", "link", "unlink", "ioctl", "lock"]),
("RW", ["open", "getattr", "read", "write", "append", "ioctl", "lock"]),
("RW_INH", ["getattr", "read", "write", "append", "ioctl", "lock"]),
("WRITE", ["open", "getattr", "write", "append", "lock", "ioctl"]),
("WRITE_INH", ["getattr", "write", "append", "lock", "ioctl"]),
("READ", ["open", "getattr", "read", "ioctl", "lock"]),
("READ_INH", ["getattr", "read", "ioctl", "lock"]),
("CREATE", ["getattr", "create", "open"]),
("EXEC", ["execute", "execute_no_trans"])]


def print_permission_sets():
	print "Capitalised words in edge labels are permission sets containing the following permissions:\n"
	for label, perm_list in perm_sets:
		print label + ": " + ", ".join(perm_list)

def process_edge_labels(labels):
	#print(perm_sets)
	for edge in labels:
		label = set(labels[edge])
		for (name,perm_list) in perm_sets:
			if set(perm_list).issubset(label):
				label = label - set(perm_list)
				label.add(name)

				#print("DIFF> ", diff(label, perm_list))
		labels[edge] = ", ".join(label)


