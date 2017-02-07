#!/usr/bin/python3
# -*- coding: utf-8 -*-

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

#from os import walk
import sys
import os
import re

# read .cil files in given path and return list of tuples
# (filename, [types])
# cil files are located in
# /var/lib/selinux/targeted/active/modules/100/*/cil
def get_types_cil(path):

	filepaths = []
	#get files in given directory
	for (dirpath, dirnames, filenames) in os.walk(path):
		# tuples (filename,full_file_path)
		filepaths.extend(
				((filename[:-4], os.path.join(dirpath, filename)) for filename in sorted(filenames)
				if filename.endswith(".cil"))
		)
		break # don't go deeper
	
	results = []
	
	for filename,path in filepaths:
		types = get_types(path)

		if types:
			results.append((filename.lower(), types))
	return results



#get types defined in given file
def get_types(file_path):	
	try:
		
		txt = open(file_path, "r")

		#regexp finding lines containing type definitions
		#eg. (type lib_t)
		#Contains only 1 group that matches the type name
		regexp = re.compile(r"\s*\(\s*type\s+([\w-]+)\s*\)\s*")

		types = []
		for line in txt:
			result = regexp.match(line)
			if result:
				types.append((result.group(1)).lower())
		
		return types

	except IOError as e:
		return []
