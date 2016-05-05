#!/usr/bin/env python3
import selinux
import sepolicy  

import networkx as nx

from collections import defaultdict
from security_related import get_security_types

# find viable type transitions (entrypoint to target_domain and executable by source_domain exists)
# returns set of tuples (source_domain, target_domain, entrypoint)
def find_type_transitions(G):
	#get process transition edges
	process_transitions = defaultdict(set)
	#old networkx version !!!
	#for (u, v, data) in G.edges_iter(data="process"):
	for (u, v, data) in G.edges_iter(data=True):
		#print(u, " ", v, " ",data)
		if ("transition" in data.get("process", {})):
			process_transitions[v].add(u)

	results = set()
	
	execute_perms = set(["execute", "read", "getattr"])
	for target,sources in process_transitions.items():
		#find "entrypoint" in target node successors
		for (t, succ, data) in G.out_edges({target}, data=True):
			if ("entrypoint" in data.get("file", {})):
				for source in sources:
					if(execute_perms.issubset(G.get_edge_data(source, succ, {}).get("file", {}))):
						#found process transition form "source" to "target" via entrypoint "succ"
						results.add((source, target, succ))
	
	return results


# For a dynamic transition (from A to B) to happen, the following has to be allowed
# allow A B:process { dyntransition }; //transition is allowed to happen
# allow A self:process { setcurrent }; //execution of the transition
def find_dyntransitions_from(G, source):
	results = set()
	
	for succ in G.successors_iter(source):
		if (("dyntransition" in (G.get_edge_data(source, succ, {}).get("process", {}))) and
			("setcurrent" in (G.get_edge_data(source, source, {}).get("process", {})))):
			results.add(succ)

	return results

# For a dynamic transition (from A to B) to happen, the following has to be allowed
# allow A B:process { dyntransition }; //transition is allowed to happen
# allow A self:process { setcurrent }; //execution of the transition
def find_all_dyntransitions(G):
	results = defaultdict(set)
	
	for (u, v, data) in G.edges_iter(data=True):
		if ("dyntransition" in data.get("process", {}) and
			"setcurrent" in (G.get_edge_data(u, u, {}).get("process", {}))):
			results[u].add(v)

	return results

# Find all files whose execution may lead to process running in one of given domains
def find_executables_to(G,domains):
	entrypoints = set()

	execute_no_trans = set(["execute_no_trans", "read", "getattr"])
	#corresponds to "allow domain domain_entrypoint: file {entrypoint}"
	#or "allow domain executable:file {"execute_no_trans", "read", "getattr"}"
	for (u, v, data) in G.out_edges_iter(domains,data=True):
		fileperms = data.get("file", {})
		if (("entrypoint" in fileperms) or 
			execute_no_trans.issubset(fileperms)): #domain "u" can execute given file without transition
			entrypoints.add(v)
	return entrypoints

# Find entrypoint types fo given domains
# return dictionary using entrypoints as keys and corresponding domains as values
def find_entrypoints_to(G,domains):
	entrypoints = defaultdict(set)
	#corresponds to "allow domain domain_entrypoint: file {entrypoint}"
	for (u, v, data) in G.out_edges_iter(domains,data=True):
		fileperms = data.get("file", {})
		if ("entrypoint" in fileperms): #domain "u" can execute given file without transition
			entrypoints[v].add(u)
	return entrypoints


# find domain types that can be executed by someone 
# Types with attribute "domain" that are targets of "allow execute" rule
#def find_executable_domain_type(G):
#	pass

#find entrypoints that can be written by someone (and corresponding domains to which these entrypoints lead)
def find_writable_executables(G):
	# will contain entrypoint labels as keys
	# and sets of domains in which the process (spawned from given entrypoint) will run as values
	execs = defaultdict(set)
	#old networkx version !!!
	#for (u, v, data) in G.edges_iter(data="process"):
	execute_no_trans = set(["execute_no_trans", "read", "getattr"])
	for (u, v, data) in G.edges_iter(data=True):
		fileperms = data.get("file", {})
		if (("entrypoint" in fileperms) or 
			execute_no_trans.issubset(fileperms)): #domain "u" can execute given file without transition
			execs[v].add(u)

	writable = defaultdict(set)
	for key,value in execs.items():
		#iterate over incomming edges of key (entrypoint)
		for (u,v,data) in G.in_edges_iter([key],data=True):
			if ("write" in data.get("file", {})):
				writable[key].add(u)

	return writable

# find type_transition_execution first using groupped graph
# and then expand them using full graph -- speed comparison to direct search in full graph
# G - full graph
# G_G - groupped graph
def find_type_transition_execution_uing_groups(G, G_G):
	process_transitions = defaultdict(set)
	#old networkx version !!!
	#for (u, v, data) in G.edges_iter(data="process"):
	for (u, v, data) in G_G.edges_iter(data=True):
		#print(u, " ", v, " ",data)
		if ("transition" in data.get("process", {})):
			process_transitions[v].add(u)

	results = set()
	
	execute_perms = set(["execute", "read", "getattr"])
	for target,sources in process_transitions.items():
		#find "entrypoint" in target node successors
		for succ in G_G.successors_iter(target):
			if ("entrypoint" in G_G.get_edge_data(target, succ, {}).get("file", {})):
				#test if sources have "execute" permissions on entrypoint
				for source in sources:
					if(execute_perms.issubset(G_G.get_edge_data(source, succ, {}).get("file", {}))):
						#found process transition form "source" to "target" via entrypoint "succ"
						results.add((source, target, succ))

	write_exec = set()
	for source,target,entry in results:
		if ("write" in G_G.get_edge_data(source,entry, {}).get("file", {})):
			write_exec.add((source,target))

	return expand_type_transition_execution(G, write_exec)

# helper function  -- find_type_transition_execution from selected (candidate) domain_groups 
def expand_type_transition_execution(G, groupped_transitions):
	process_transitions = defaultdict(set)
	#print(groupped_transitions)
	for source_g, target_g in groupped_transitions:
		for source in source_g.domains:
			for target in target_g.domains:
				#if (source == "accountsd_t" and target == "abrt_helper_t"):
				#		print("DAGFUQ?")
				if ("transition" in G.get_edge_data(source, target, {}).get("process", {})):
					process_transitions[target].add(source)	


	results = set()

	execute_perms = set(["execute", "read", "getattr"])
	for target,sources in process_transitions.items():
		#find "entrypoint" in target node successors
		
		for succ in G.successors_iter(target):
			if ("entrypoint" in G.get_edge_data(target, succ, {}).get("file", {})):
				#test if sources have "execute" permissions on entrypoint
				for source in sources:
					if(execute_perms.issubset(G.get_edge_data(source, succ, {}).get("file", {}))):
						#found process transition form "source" to "target" via entrypoint "succ"
						results.add((source, target, succ))

	suspicious = set()
	for source,target,trans in results:
		if ("write" in G.get_edge_data(source,trans, {}).get("file", {})):
			suspicious.add((source,target,trans))

	return suspicious


# Find domain transitions via entrypoints that can be rewritten by source domain
def find_type_transition_execution(G):
	#get process transition edges
	process_transitions = defaultdict(set)
	#old networkx version !!!
	#for (u, v, data) in G.edges_iter(data="process"):
	for (u, v, data) in G.edges_iter(data=True):
		#print(u, " ", v, " ",data)
		if ("transition" in data.get("process", {})):
			process_transitions[v].add(u)

	results = set()
	transitions = set()
	
	execute_perms = set(["execute", "read", "getattr"])
	for target,sources in process_transitions.items():
		#find "entrypoint" in target node successors
		for (t, succ, data) in G.out_edges({target}, data=True):
			if ("entrypoint" in data.get("file", {})):
				for source in sources:
					if(execute_perms.issubset(G.get_edge_data(source, succ, {}).get("file", {}))):
						#found process transition form "source" to "target" via entrypoint "succ"
						results.add((source, target, succ))
						transitions.add((source, target))

	suspicious = set()
	for source,target,entry in results:
		if ("write" in G.get_edge_data(source,entry, {}).get("file", {})):
			suspicious.add((source,target,entry))

	return suspicious



#################################### General search functions for assembling user defined queries ##################################



# find graph edges containing given permission set (for given target object class)
# returns dictionary indexed by sources, with sets of targets as values
def find_edges_permission_set(G, target_class, permissions):
	permissions = set(permissions)
	results = defaultdict(set)

	for (u, v, data) in G.edges_iter(data=True):
		perms = data.get(target_class, {})
		if permissions.issubset(fileperms):
			results[u].add(v)

	return results

# find graph edges going from "from_types" that contain given permission set (for given target object class)
# returns dictionary indexed by sources, with sets of targets as values
def find_edges_permission_set_from(G, from_types, target_class, permissions):
	permissions = set(permissions)
	results = defaultdict(set)
	
	for (u, v, data) in G.out_edges_iter(from_types, data=True):
		if permissions.issubset(data.get(target_class, {})):
			results[u].add(v)

	return results

# find graph edges going to "tartet_types" that contain given permission set (for given target object class)
# returns dictionary indexed by targets, with sets of sources as values
def find_edges_permission_set_to(G, target_types, target_class, permissions):
	permissions = set(permissions)
	results = defaultdict(set)
	
	for (u, v, data) in G.in_edges_iter(target_types, data=True):
		if permissions.issubset(data.get(target_class, {})):
			results[v].add(u)

	return results

# returns iterator over all pairs (key, set_item) in given dictionary
def iterate_set_dictionary(dictionary):
	for key,value_set in dictionary.items():
		for value in value_set:
			yield (key, value)

# get permissions of "source" targeted towards "target" type (with given target class)
# corresponds to SELinux rule 
# 	allow source target:target_class permissions
# returns set of permissions
def get_permissions(G, source, target, target_class):
	return G.get_edge_data(source, target, {}).get(target_class, {})

# True if the following SELinux rule exists
# 	allow source target:target_class permissions
def is_allowed(G, source, target, target_class, permissions):
	return set(permissions).issubset(G.get_edge_data(source, target, {}).get(target_class, {}))
