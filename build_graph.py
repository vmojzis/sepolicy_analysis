#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import policy_data_collection as data
import domain_grouping as grouping
import graph_builder as builder

# parse comma separated list of [boolean_name]:[on/off] 
def parse_bool_config(bool_arg):
	bool_config = {}
	for boolean in bool_arg.split(","):
		b = boolean.split(":")
		if len(b) >= 2:
			bool_config[b[0]] = (b[1] == "on")
	#print("Bool config:\n", bool_config, "\n", bool_arg)
	return bool_config


parser = argparse.ArgumentParser(description='SELinux policy analysis tool - graph builder.')

parser.add_argument("filename", help="Name for the new policy graph file.")

parser.add_argument("-dg", action="store_true", dest="domain_grouping",
                  help="Group SELinux domains based on package they belong to.")


parser.add_argument("-fb", "--filter_bools", nargs="?", dest="filter_bools", const="",
                  help="Filter rules based on current boolean setting \
                  	    (or boolean config file or comma separated list of [boolean]:[on/off]).")

parser.add_argument("-c", "--class", dest="classes",
                  help="Comma separated list of object classes")

parser.add_argument("policy", help="Path to the SELinux policy to be used.", nargs="?")


args = parser.parse_args()

# split list attributes
if args.classes:
	args.classes = args.classes.split(",")

if args.filter_bools != None:
	args.filter_bools = parse_bool_config(args.filter_bools)

builder.build_graph(args.policy, args.domain_grouping, args.filename, args.classes, args.filter_bools)


