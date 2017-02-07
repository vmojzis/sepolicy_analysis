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

# parse comma separated list of [boolean_name]:[on/off] 
def parse_bool_config(bool_arg):
	bool_config = {}
	for boolean in bool_arg.split(","):
		b = boolean.split(":")
		if len(b) >= 2:
			bool_config[b[0]] = (b[1] == "on")
	#print("Bool config:\n", bool_config, "\n", bool_arg)
	return bool_config
