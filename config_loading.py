#!/usr/bin/env python

from __future__ import print_function
import sys


# read "bool_config" into dictionary (same structure as "getsebool -a" output)
def get_boolean_config():
	try:
		txt = open("bool_config", "r")
		config = {}
		for line in txt:
			split_line = line.rstrip().split(" ")
			if len(split_line) != 3:
				print("Invalid line: " + split_line, file=sys.stderr)
				break 
			config[split_line[0]] = (split_line[2] == "on")
			print(" ".join(split_line))
		return config

	except IOError as e:
		return None