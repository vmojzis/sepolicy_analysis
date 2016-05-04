#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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