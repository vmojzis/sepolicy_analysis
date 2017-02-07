#!/usr/bin/python3

# (C) Copyright 2016 Vit Mojzis, vmojzis@redhat.com
# 
# This program is distributed under the terms of the GNU General Public License
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sepolicyanalysis.domain_grouping as grouping
import sys

# read "security_related.conf" and return corresponding types
# returns (domain_types, resource_types)
def get_security_types():
	try:
		packages = set()
		types = set()
		exclude = set()
		
		txt = open("/etc/sepolicyanalysis/security_related.conf", "r")
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

