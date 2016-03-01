#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import config_loading as config

import argparse
import visualization as vis
import policy_data_collection as data
import userquery as query
import domain_grouping as grouping

# parse comma separated list of [boolean_name]:[on/off] 
def parse_bool_config(bool_arg):
	bool_config = {}
	for boolean in bool_arg.split(","):
		b = boolean.split(":")
		if len(b) == 2:
			bool_config[b[0]] = (b[1] == "on")
	#print("Bool config:\n", bool_config, "\n", bool_arg)
	return bool_config


parser = argparse.ArgumentParser(description='SELinux policy analysis tool.')

search = parser.add_argument_group("Rule search (simillar to sesearch)")

search.add_argument("-s", "--source",
                  help="Source type/role of the TE/RBAC rule.")
search.add_argument("-t", "--target",
                  help="Target type/role of the TE/RBAC rule.")
search.add_argument("-c", "--class", dest="tclass",
                  help="Comma separated list of object classes")
search.add_argument("-p", "--perms", metavar="PERMS",
                  help="Comma separated list of permissions.")
search.add_argument("-a", "--attr", metavar="ATTR",
                  help="Comma separated list of attributes.")
search.add_argument("-D", "--default",
                  help="Default of the rule. (type/role/range transition rules)")
search.add_argument("-b", "--bool", dest="boolean", metavar="BOOL",
                  help="Comma separated list of Booleans in the conditional expression.")

filtering = parser.add_argument_group("Filtering")

filtering.add_argument("-fb", "--filter_bools", nargs="?", dest="filter_bools", const="",
                  help="Filter rules based on current boolean setting \
                  	    (or boolean config file or comma separated list of [boolean]:[on/off]).")

filtering.add_argument("-fa", "--filter_attrs", dest="filter_attrs", metavar="ATTR",
                  help="Filter out rules allowed for specified attributes. \
                  		ATTR - Comma separted list of attributes.")


args = parser.parse_args()

# split list attributes
for arg in ["perms", "attr", "boolean", "tclass"]:
	value = getattr(args, arg)
	if value:
		setattr(args, arg, value.split(","))

if args.filter_bools != None:
	args.filter_bools = parse_bool_config(args.filter_bools)

# Only one of "source" and "destination" may be set
# The one which is set becomes "main_domain" - centerpoint of the query
args.main_domain = args.source if args.source else args.target


'''
if args.tclass:
	args.tclass = args.tclass.split(",")

if args.tclass:
	args.tclass = args.tclass.split(",")
'''

q = query.UserQuery(args)
#q.apply_query()

q.apply_query_grouping(grouping.group_types_name())
#vis.apply_query(args)

#print(args)
