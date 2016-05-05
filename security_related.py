#!/usr/bin/env python3

import domain_grouping as grouping
import sys

# read "security_related.conf" and return corresponding types
# returns (domain_types, resource_types)
def get_security_types():
	try:
		packages = set()
		types = set()
		exclude = set()
		
		txt = open("security_related.conf", "r")
		packages = {}
		for line in txt:
			if (len(line) < 1) or (line[0] == '#'):
				continue

			if line.startswith("packages="):
				packages = set([x.strip() for x in line[9:].split(",")])

			if line.startswith("types=="):
				types = set([x.strip() for x in line[6:].split(",")])
			
			if line.startswith("exclude="):
				exclude = set([x.strip() for x in line[8:].split(",")])
		
		#all types given in "types=" are treated as domains !
		domain_grouping = grouping.group_types_cil()

		groups = set()
		for name in packages:
			group = domain_grouping.get(name, None)
			if group:
				groups.add(group)

		#get types corresponding to given packages
		domains, resources = grouping.get_types(groups)

		domains = domains | types
		# remove excluded types
		domains = domains - exclude
		resources = resources - exclude

		return domains, resources 

	except IOError as e:
		print('Could not read "security_related.conf"!', file=sys.stderr)
		return set(), set()

