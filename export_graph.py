#!/usr/bin/env python3
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

import config_loading as config
import argparse
import sys
import visualization as vis
import policy_data_collection as data
import userquery as query
import domain_grouping as grouping

parser = argparse.ArgumentParser(description='SELinux policy graph export tool.')

parser.add_argument("package", help="Policy concerning this package will be exported")

parser.add_argument("policy", help="Path to the SELinux policy to be used.", nargs="?")

search = parser.add_argument_group("Rule search (simillar to sesearch)")

search.add_argument("-c", "--class", dest="tclass",
                  help="Comma separated list of object classes")
search.add_argument("-p", "--perms", metavar="PERMS",
                  help="Comma separated list of permissions.")
search.add_argument("-a", "--attr", metavar="ATTR",
                  help="Comma separated list of attributes.")
search.add_argument("-b", "--bool", dest="boolean", metavar="BOOL",
                  help="Comma separated list of Booleans in the conditional expression.")
search.add_argument("-ea", action="store_true", dest="expand_attributes",
                  help="Expand rules ending in attribute (to all types that have given attribute).")

filtering = parser.add_argument_group("Filtering")

filtering.add_argument("-fb", "--filter_bools", nargs="?", dest="filter_bools", const="",
                  help="Filter rules based on current boolean setting \
                  	    (or boolean config file or comma separated list of [boolean]:[on/off]).")

filtering.add_argument("-fa", "--filter_attrs", dest="filter_attrs", metavar="ATTR",
                  help="Filter out rules allowed for specified attributes. \
                  		ATTR - Comma separated list of attributes.")

args = parser.parse_args()

args.export = True

# split list attributes
for arg in ["perms", "attr", "boolean", "tclass", "filter_attrs"]:
	value = getattr(args, arg)
	if value:
		setattr(args, arg, value.split(","))

if args.filter_bools != None:
	args.filter_bools = config.parse_bool_config(args.filter_bools)

# For compatibility with userquery module
args.source = args.package
args.main_domain = args.source

data.policy_init(args.policy)

q = query.UserQuery(args)
q.apply_query()

