#!/usr/bin/env python3

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
import copy

'''
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
	("SIGNAL", {"sigchld", "sigkill", "sigstop", "signull", "signal"}), ]
'''


#perm_sets_hierarchy = {
#	["MANAGE", "RW", "RW_INH", "WRITE", "WRITE_INH", "READ", "READ_INH"],
#	["MANAGE", "EXEC"]
#	["MANAGE", "CREATE"]
#	}

# creates a dictionary of permission sets contained in each permission set
# {perm_set:[smaller_perm_sets]}
def perm_sets_hierarchy():
	#mustn't contain identical sets (performance issue)
	for (name,perm_list) in perm_sets:
		for (name2,perm_list2) in perm_sets:
			if name != name2 and perm_list2 == perm_list:
				print("ERROR: identical permission sets: ", name, " and ", name2)
				return {}

	hierarchy = defaultdict(set)

	for (name,perm_list) in perm_sets:
		for (name2,perm_list2) in perm_sets:
			if name != name2 and perm_list2.issubset(perm_list):
				hierarchy[name].add(name2)
	return hierarchy

def print_permission_sets():
	print("\nCapitalised words in edge labels are permission sets containing the following permissions:\n")
	for label, perm_list in perm_sets:
		print(label + ": " + ", ".join(sorted(perm_list)))

#replace permissions by corresponding permission set names - reduces edge description length
def process_edge_labels(labels):
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
		#l_copy = [x for x in new_label]
		l_copy = copy.deepcopy(new_label)
		for item in l_copy:
			new_label -= perm_sets_hierarchy.get(item, set())

		del l_copy

		labels[edge] = ", ".join(sorted(new_label | (label - to_remove)))
	return labels


##### permission sets to replace on graph edges --- !!! generate corresponding perm_sets_hierarchy (below) -- performance issue

perm_sets = [
	('CREATE_MSGQ', {'associate', 'create', 'destroy', 'enqueue', 'getattr', 'read', 'setattr', 'unix_read', 'unix_write', 'write'}),
	('MOUNT_FS', {'getattr', 'mount', 'remount', 'unmount'}),
	('RW_SEM', {'associate', 'getattr', 'read', 'unix_read', 'unix_write', 'write'}),
	('MANAGE_FILE', {'append', 'create', 'getattr', 'ioctl', 'link', 'lock', 'open', 'read', 'rename', 'setattr', 'unlink', 'write'}),
	#('WRITE_LNK_FILE', {'append', 'getattr', 'ioctl', 'lock', 'write'}),
	#('CREATE_NETLINK_SOCKET', {'append', 'bind', 'connect', 'create', 'getattr', 'getopt', 'ioctl', 'lock', 'nlmsg_read', 'nlmsg_write', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	('READ_FILE', {'getattr', 'ioctl', 'lock', 'open', 'read'}),
	('CREATE_SOCK_FILE', {'create', 'getattr', 'open', 'setattr'}),
	#('MANAGE_BLK_FILE', {'append', 'create', 'getattr', 'ioctl', 'link', 'lock', 'open', 'read', 'rename', 'setattr', 'unlink', 'write'}),
	#('READ_BLK_FILE', {'getattr', 'ioctl', 'lock', 'open', 'read'}),
	('CONNECTED_STREAM_SOCKET', {'accept', 'append', 'bind', 'create', 'getattr', 'getopt', 'ioctl', 'listen', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	#('READ_FIFO_FILE', {'getattr', 'ioctl', 'lock', 'open', 'read'}),
	('RW_INHERITED_FILE', {'append', 'getattr', 'ioctl', 'lock', 'read', 'write'}),
	('RW_SOCKET', {'append', 'bind', 'connect', 'getattr', 'getopt', 'ioctl', 'lock', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	#('RW_INHERITED_CHR_FILE', {'append', 'getattr', 'ioctl', 'lock', 'read', 'write'}),
	#('MANAGE_SOCK_FILE', {'append', 'create', 'getattr', 'ioctl', 'link', 'lock', 'open', 'read', 'rename', 'setattr', 'unlink', 'write'}),
	('MANAGE_SERVICE', {'disable', 'enable', 'reload', 'start', 'status', 'stop'}),
	('MANAGE_LNK_FILE', {'append', 'create', 'getattr', 'ioctl', 'link', 'lock', 'read', 'rename', 'setattr', 'unlink', 'write'}),
	#('WRITE_FIFO_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open', 'write'}),
	('RW_DIR', {'add_name', 'getattr', 'ioctl', 'lock', 'open', 'read', 'remove_name', 'search', 'write'}),
	('RW_SOCK_FILE', {'append', 'getattr', 'open', 'read', 'write'}),
	('ADD_ENTRY_DIR', {'add_name', 'getattr', 'ioctl', 'lock', 'open', 'search', 'write'}),
	('MMAP_FILE', {'execute', 'getattr', 'ioctl', 'open', 'read'}),
	('RW_SHM', {'associate', 'getattr', 'lock', 'read', 'unix_read', 'unix_write', 'write'}),
	('R_NETLINK_SOCKET', {'append', 'bind', 'connect', 'create', 'getattr', 'getopt', 'ioctl', 'lock', 'nlmsg_read', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	('CREATE_SEM', {'associate', 'create', 'destroy', 'getattr', 'read', 'setattr', 'unix_read', 'unix_write', 'write'}),
	('RW_LNK_FILE', {'getattr', 'ioctl', 'lock', 'read', 'write'}),
	('MANAGE_KEY', {'create', 'link', 'read', 'search', 'setattr', 'view', 'write'}),
	#('RW_CHR_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open', 'read', 'write'}),
	('RW_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open', 'read', 'write'}),
	#('MANAGE_FIFO_FILE', {'append', 'create', 'getattr', 'ioctl', 'link', 'lock', 'open', 'read', 'rename', 'setattr', 'unlink', 'write'}),
	#('R_MSGQ', {'associate', 'getattr', 'read', 'unix_read'}),
	('CREATE_SOCKET', {'append', 'bind', 'connect', 'create', 'getattr', 'getopt', 'ioctl', 'lock', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	('RW_INHERITED_SOCK_FILE', {'append', 'getattr', 'read', 'write'}),
	#('WRITE_CHR_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open', 'write'}),
	('PACKET_SEND_RCV', {'rawip_recv', 'rawip_send', 'tcp_recv', 'tcp_send', 'udp_recv', 'udp_send'}),
	#('R_SEM', {'associate', 'getattr', 'read', 'unix_read'}),
	#('APPEND_BLK_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open'}),
	#('APPEND_CHR_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open'}),
	('CREATE_SHM', {'associate', 'create', 'destroy', 'getattr', 'lock', 'read', 'setattr', 'unix_read', 'unix_write', 'write'}),
	('DEL_ENTRY_DIR', {'getattr', 'ioctl', 'lock', 'open', 'remove_name', 'search', 'write'}),
	('RW_MSGQ', {'associate', 'enqueue', 'getattr', 'read', 'unix_read', 'unix_write', 'write'}),
	('APPEND_LNK_FILE', {'append', 'getattr', 'ioctl', 'lock'}),
	('R_SHM', {'associate', 'getattr', 'read', 'unix_read'}),
	#('APPEND_FIFO_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open'}),
	('APPEND_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open'}),
	('EXEC_FILE', {'execute', 'execute_no_trans', 'getattr', 'ioctl', 'open', 'read'}),
	#('RW_INHERITED_FIFO_FILE', {'append', 'getattr', 'ioctl', 'lock', 'read', 'write'}),
	#('READ_CHR_FILE', {'getattr', 'ioctl', 'lock', 'open', 'read'}),
	#('RW_INHERITED_BLK_FILE', {'append', 'getattr', 'ioctl', 'lock', 'read', 'write'}),
	('CREATE_STREAM_SOCKET', {'accept', 'append', 'bind', 'connect', 'create', 'getattr', 'getopt', 'ioctl', 'listen', 'lock', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	#('CLIENT_STREAM_SOCKET', {'append', 'bind', 'create', 'getattr', 'getopt', 'ioctl', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	('MANAGE_DIR', {'add_name', 'create', 'getattr', 'ioctl', 'link', 'lock', 'open', 'read', 'remove_name', 'rename', 'reparent', 'rmdir', 'search', 'setattr', 'unlink', 'write'}),
	#('RW_FIFO_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open', 'read', 'write'}),
	('SIGNAL', {'sigchld', 'sigkill', 'signal', 'signull', 'sigstop'}),
	('WRITE_INHERITED_FILE', {'append', 'getattr', 'ioctl', 'lock', 'write'}),
	#('RW_TERM', {'append', 'getattr', 'ioctl', 'lock', 'open', 'read', 'write'}),
	('WRITE_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open', 'write'}),
	('RW_NETLINK_SOCKET', {'append', 'bind', 'connect', 'create', 'getattr', 'getopt', 'ioctl', 'lock', 'nlmsg_read', 'nlmsg_write', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	('LIST_DIR', {'getattr', 'ioctl', 'lock', 'open', 'read', 'search'}),
	#('MANAGE_CHR_FILE', {'append', 'create', 'getattr', 'ioctl', 'link', 'lock', 'open', 'read', 'rename', 'setattr', 'unlink', 'write'}),
	#('RW_INHERITED_TERM', {'append', 'getattr', 'ioctl', 'lock', 'read', 'write'}),
	#('SERVER_STREAM_SOCKET', {'accept', 'append', 'bind', 'create', 'getattr', 'getopt', 'ioctl', 'listen', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	#('RW_BLK_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open', 'read', 'write'}),
	('READ_INHERITED_FILE', {'getattr', 'ioctl', 'lock', 'read'}),
	#('WRITE_BLK_FILE', {'append', 'getattr', 'ioctl', 'lock', 'open', 'write'}),
	('RW_STREAM_SOCKET', {'accept', 'append', 'bind', 'connect', 'getattr', 'getopt', 'ioctl', 'listen', 'lock', 'read', 'setattr', 'setopt', 'shutdown', 'write'}),
	('WRITE_SOCK_FILE', {'append', 'getattr', 'open', 'write'}),
	('CONNECTED_SOCKET', {'append', 'bind', 'create', 'getattr', 'getopt', 'ioctl', 'read', 'setattr', 'setopt', 'shutdown', 'write'})
	]

def generate_perm_sets_hierarchy():
	hierarchy = perm_sets_hierarchy()

	for key,value in hierarchy.items():
		print("'", key, "':", value,",",sep="")

perm_sets_hierarchy = {
	'RW_SOCKET':{'APPEND_LNK_FILE', 'RW_LNK_FILE', 'RW_INHERITED_SOCK_FILE', 'WRITE_INHERITED_FILE', 'READ_INHERITED_FILE', 'RW_INHERITED_FILE'},
	'CONNECTED_STREAM_SOCKET':{'CONNECTED_SOCKET', 'RW_INHERITED_SOCK_FILE'},
	'CREATE_STREAM_SOCKET':{'APPEND_LNK_FILE', 'RW_LNK_FILE', 'RW_INHERITED_SOCK_FILE', 'CONNECTED_STREAM_SOCKET', 'CREATE_SOCKET', 'WRITE_INHERITED_FILE', 'RW_SOCKET', 'READ_INHERITED_FILE', 'RW_STREAM_SOCKET', 'RW_INHERITED_FILE', 'CONNECTED_SOCKET'},
	'WRITE_INHERITED_FILE':{'APPEND_LNK_FILE'},
	'RW_SHM':{'RW_SEM', 'R_SHM'},
	'RW_STREAM_SOCKET':{'APPEND_LNK_FILE', 'RW_LNK_FILE', 'RW_INHERITED_SOCK_FILE', 'WRITE_INHERITED_FILE', 'RW_SOCKET', 'READ_INHERITED_FILE', 'RW_INHERITED_FILE'},
	'RW_INHERITED_FILE':{'READ_INHERITED_FILE', 'APPEND_LNK_FILE', 'RW_LNK_FILE', 'WRITE_INHERITED_FILE', 'RW_INHERITED_SOCK_FILE'},
	'MANAGE_DIR':{'RW_DIR', 'RW_LNK_FILE', 'DEL_ENTRY_DIR', 'LIST_DIR', 'CREATE_SOCK_FILE', 'READ_FILE', 'READ_INHERITED_FILE', 'ADD_ENTRY_DIR'},
	'READ_FILE':{'READ_INHERITED_FILE'},
	'MANAGE_LNK_FILE':{'APPEND_LNK_FILE', 'RW_LNK_FILE', 'RW_INHERITED_SOCK_FILE', 'WRITE_INHERITED_FILE', 'READ_INHERITED_FILE', 'RW_INHERITED_FILE'},
	'LIST_DIR':{'READ_INHERITED_FILE', 'READ_FILE'},
	'RW_SEM':{'R_SHM'},
	'CONNECTED_SOCKET':{'RW_INHERITED_SOCK_FILE'},
	'APPEND_FILE':{'APPEND_LNK_FILE'},
	'RW_DIR':{'RW_LNK_FILE', 'DEL_ENTRY_DIR', 'LIST_DIR', 'READ_INHERITED_FILE', 'READ_FILE', 'ADD_ENTRY_DIR'},
	'R_NETLINK_SOCKET':{'APPEND_LNK_FILE', 'RW_LNK_FILE', 'RW_INHERITED_SOCK_FILE', 'CREATE_SOCKET', 'WRITE_INHERITED_FILE', 'RW_SOCKET', 'READ_INHERITED_FILE', 'RW_INHERITED_FILE', 'CONNECTED_SOCKET'},
	'RW_LNK_FILE':{'READ_INHERITED_FILE'},
	'EXEC_FILE':{'MMAP_FILE'},
	'CREATE_MSGQ':{'RW_SEM', 'RW_MSGQ', 'R_SHM', 'CREATE_SEM'},
	'WRITE_FILE':{'APPEND_FILE', 'APPEND_LNK_FILE', 'WRITE_INHERITED_FILE', 'WRITE_SOCK_FILE'},
	'MANAGE_FILE':{'APPEND_FILE', 'APPEND_LNK_FILE', 'RW_LNK_FILE', 'WRITE_SOCK_FILE', 'RW_INHERITED_SOCK_FILE', 'WRITE_FILE', 'WRITE_INHERITED_FILE', 'CREATE_SOCK_FILE', 'READ_FILE', 'RW_FILE', 'RW_INHERITED_FILE', 'MANAGE_LNK_FILE', 'RW_SOCK_FILE', 'READ_INHERITED_FILE'},
	'CREATE_SOCKET':{'APPEND_LNK_FILE', 'RW_LNK_FILE', 'RW_INHERITED_SOCK_FILE', 'WRITE_INHERITED_FILE', 'RW_SOCKET', 'READ_INHERITED_FILE', 'RW_INHERITED_FILE', 'CONNECTED_SOCKET'},
	'RW_FILE':{'APPEND_FILE', 'APPEND_LNK_FILE', 'RW_LNK_FILE', 'WRITE_SOCK_FILE', 'RW_INHERITED_SOCK_FILE', 'WRITE_FILE', 'WRITE_INHERITED_FILE', 'READ_FILE', 'READ_INHERITED_FILE', 'RW_INHERITED_FILE', 'RW_SOCK_FILE'},
	'RW_SOCK_FILE':{'WRITE_SOCK_FILE', 'RW_INHERITED_SOCK_FILE'},
	'CREATE_SEM':{'RW_SEM', 'R_SHM'},
	'CREATE_SHM':{'CREATE_SEM', 'RW_SEM', 'R_SHM', 'RW_SHM'},
	'RW_MSGQ':{'RW_SEM', 'R_SHM'},
	'RW_NETLINK_SOCKET':{'APPEND_LNK_FILE', 'RW_LNK_FILE', 'RW_INHERITED_SOCK_FILE', 'CREATE_SOCKET', 'WRITE_INHERITED_FILE', 'RW_SOCKET', 'READ_INHERITED_FILE', 'RW_INHERITED_FILE', 'R_NETLINK_SOCKET', 'CONNECTED_SOCKET'},
	}



#formating permission sets

def format_perms():
	diction = {}
	for name,value in perms_lol.items():
		name = name.strip()
		diction[name] = [x for x in value.split(" ") if x]
	#replace perm sets with it's permissions
	for i in range(10): # hope that will be enough
		for name,value in diction.items():
			permlist = set()
			for item in value:
				if item.endswith("_perms"):
					permlist |= set(diction[item])
				else:
					permlist.add(item)
			diction[name] = permlist
	#reformat
	results = {}
	for name,value in diction.items():
		name = name.upper()[:-6]
		results[name] = list(value)
		if len(value) > 3:
			#print as dictionary containing sets of permissions
			print("'",name,"':", sorted(value),",",sep="")

	#print(results)


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
