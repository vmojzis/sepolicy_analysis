#!/usr/bin/env python

#egg_path='/home/vmojzis/DEVEL/selinux-policy/sepolicy_analysis/networkx-1.10-py3.4.egg'

#sys.path.append(egg_path)
import networkx as nx
import matplotlib.pyplot as plt

import selinux
import sepolicy   
import bisect
import sys
import copy
import subprocess


#is "x" in sorted list "slist" (can be substring of some item in slist)?
def in_sorted(x, slist):
	first = (x.split("_"))[0]
	i = bisect.bisect_left(slist, first)
	if i == 0 and not slist[0].startswith(first):
		return False # not found
	#browse through items starting with the same word
	while(i < len(slist) and slist[i].startswith(first)):
		#exclude extension "exec" (domain entry point)
		if slist[i][-4:] == "exec":
			i += 1
			continue
		if slist[i].startswith(x):
			#print "found: " + slist[i]
			return True
		i += 1
	return False

# Find all items starting with "x" in sorted list "slist"
def find_in_sorted(x, slist):
	found = []
	i = bisect.bisect_left(slist, x)
	while i < len(slist) and slist[i].startswith(x):
		found.append(slist[i] + "_t")
		i += 1
	return found

# Find all items starting with "x" in sorted list "slist" and remove them from "slist"
def find_remove_sorted(x, slist):
	found = []
	i = bisect.bisect_left(slist, x)
	while i < len(slist) and slist[i].startswith(x):
		found.append(slist.pop(i) + "_t")
	return found

# Returns (domain) name corresponding to given label (finds longest part
# of given label that is also used somewhere in "object_list")
def subject_name(subject, object_list):
	s = subject.split("_")
	#print s
	for i in range(len(s)):
		#print s[:len(s)-i]
		#print "test" +  ("_".join(s[:-i]))
		if in_sorted("_".join(s[:len(s)-i]), object_list):
			return "_".join(s[:len(s)-i])
	return s[0]

# Returns dictionary "group_name":"set_of_corresponding_domain_types"
def create_domain_groups(subject_list, object_list):
	#
	#subject_list.sort(reverse = True)
	domain_groups = {}
	for subject in subject_list:
		group_name = subject_name(subject, object_list)
		if group_name not in domain_groups:
			domain_groups[group_name] = set()
		domain_groups[group_name].add(subject+"_t")
	return domain_groups

# Returns dictionary with the same set of keys as "domain_groups",
# containing resource (non-domain) types corresponding to given group name 
def create_resource_groups(domain_groups, object_list):
	# copy object_list so that I can delete items using "find_remove_sorted"
	object_list_ = copy.deepcopy(object_list)
	resource_groups = {}

	# Sort domain group names so that the longest ones are first
	# Eg. Resources of "systemd" should not contain resources of "systemd_networkd"
	domain_group_names = domain_groups.keys()
	domain_group_names.sort(reverse = True)
	for group_name in domain_group_names:
		resource_groups[group_name] = find_remove_sorted(group_name, object_list_)
	return resource_groups

# Scan system for domain and object types and group them by name
def group_types_name():
	#get name list (contains types and attribute names)
	type_list = [x['name'].lower() for x in sepolicy.info(sepolicy.TYPE)] 
	
	# the following doesn't return all attributes !!!!!!
	#attributes  = subprocess.check_output(["seinfo", "-a"]) 
	#attributes = attributes.split("\n")
	#type_list = set(type_list) - set(attributes)
	#type_list = set([x[:-2] for x in type_list])

	# TODO - better attribute filtering
	# filter out attribute names and remove trailing "_t"
	type_list = set([x[:-2].lower() for x in type_list])
	
	#get types corresponding to "domains" - runnables
	subject_list = set([x[:-2].lower() for x in data.get_domain_types()])

	object_list = sorted(type_list - subject_list)#, key=lambda s: s.lower())
	type_list = sorted(type_list)#, key=lambda s: s.lower())

	domain_groups = create_domain_groups(subject_list, object_list)
	
	return domain_groups, create_resource_groups(domain_groups, object_list)


#print subject_name(sys.argv[1], object_list)
#for subject in subject_list:
#	print subject + "-> " + subject_name(subject, object_list)
domain_groups, resource_groups = group_types_name()

domain_group_names = domain_groups.keys()
domain_group_names.sort()
for group in domain_group_names:
	#if "systemd" in group:
		print group + ">>\n   " + ", ".join(domain_groups[group]) + "\n   " + ", ".join(resource_groups[group]) + "\n"


#print sepolicy.info(sepolicy.ATTRIBUTE)