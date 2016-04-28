#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import config_loading as config

import argparse
import sys
import visualization as vis
import policy_data_collection as data
import userquery as query
import domain_grouping as grouping


# parse comma separated list of [boolean_name]:[on/off] 
def parse_bool_config(bool_arg):
	bool_config = {}
	for boolean in bool_arg.split(","):
		b = boolean.split(":")
		if len(b) >= 2:
			bool_config[b[0]] = (b[1] == "on")
	#print("Bool config:\n", bool_config, "\n", bool_arg)
	return bool_config


parser = argparse.ArgumentParser(description='SELinux policy visual query tool.')

parser.add_argument("policy", help="Path to the SELinux policy to be used.", nargs="?")

search = parser.add_argument_group("Rule search (simillar to sesearch)")

source_target = search.add_mutually_exclusive_group()

source_target_group = search.add_mutually_exclusive_group()

source_target.add_argument("-s", "--source",
                  help="Source type of the TE rule.")
source_target.add_argument("-t", "--target",
                  help="Target type of the TE rule.")

source_target_group.add_argument("-sg", "--source_group",
                  help="Source type (consider whole domain group containing the type) of the TE rule.")
source_target_group.add_argument("-tg", "--target_group",
                  help="Target type (consider whole domain group containing the type) of the TE rule.")

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
search.add_argument("-ea", action="store_true", dest="expand_attributes",
                  help="Expand rules ending in attribute (to all types that have given attribute).")

filtering = parser.add_argument_group("Filtering")

filtering.add_argument("-dg", action="store_true", dest="domain_grouping",
                  help="Group SELinux domains based on package they belong to.")

filtering.add_argument("-fb", "--filter_bools", nargs="?", dest="filter_bools", const="",
                  help="Filter rules based on current boolean setting \
                  	    (or boolean config file or comma separated list of [boolean]:[on/off]).")

filtering.add_argument("-fa", "--filter_attrs", dest="filter_attrs", metavar="ATTR",
                  help="Filter out rules allowed for specified attributes. \
                  		ATTR - Comma separated list of attributes.")

parser.add_argument("-sm", "--size_multiplier", type=float, dest="size_multiplier", default=1, 
					help="Graph canvas size multiplier (>1 increases space between nodes)")

args = parser.parse_args()


if not (args.source or args.target or args.source_group or args.target_group):
	parser.print_usage()
	print("error: Specify one of [SOURCE, TARGET, SOURCE_GROUP, TARGET_GROUP]!", file=sys.stderr)
	sys.exit()

# split list attributes
for arg in ["perms", "attr", "boolean", "tclass"]:
	value = getattr(args, arg)
	if value:
		setattr(args, arg, value.split(","))

if args.filter_bools != None:
	args.filter_bools = parse_bool_config(args.filter_bools)

# Only one of "source" and "destination" may be set
# The one which is set becomes "main_domain" - centerpoint of the query
if args.source_group:
	args.source = args.source_group
if args.target_group:
	args.target = args.target_group
args.main_domain = args.source if args.source else args.target

data.policy_init(args.policy)

'''
if args.tclass:
	args.tclass = args.tclass.split(",")

if args.tclass:
	args.tclass = args.tclass.split(",")
'''

q = query.UserQuery(args)
#q.apply_query()

#q.apply_query_grouping(grouping.group_types_cil())
q.apply_query()
#vis.apply_query(args)

#print(args)
