#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from os import walk
import sys


# read .te files in given path and return list of tuples
# (filename, [types])
def get_types_contrib(path):

	filepaths = []
	#get files in given directory
	for (dirpath, dirnames, filenames) in walk(mypath):
		# tuples (filename,full_file_path)

		filepaths.extend(
				((filename, os.path.join(dirpath, filename)) for filename in filenames 
				if filename.endswith(".te"))
		)
    	break # don't go deeper
    
    results = []
    for filename,path in filepaths:
    	types = get_types(path)

    	if types:
	    	results.append((filename, types))
    return results



#get types defined in given file
def get_types(file_path):	
	try:
		
		txt = open(file_path, "r")

		types = list()
		for line in txt:
			line = line.strip()
			if line.startswith('#')
				continue
			types.append(_type)
		return types

	except IOError as e:
		return []


/var/lib/selinux/targeted/active/modules/100/*/cil