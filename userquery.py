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

import selinux
import sepolicy   
import random
import copy
import matplotlib.pyplot as plt
import matplotlib.cm as cmx
import matplotlib.colors as colors
from collections import defaultdict
from edge_labels_optimizer import process_edge_labels, print_permission_sets

import policy_data_collection as data
import config_loading as config
import visualization_ as vis
import domain_grouping as grouping
import gephi_export as export
import math
import sys

class UserQuery:
	""" SETools policy query """
	#query arguments (object returned by argparser)
	#qargs = None
	def __init__(self, args):
		self.qargs = args


	# gather all rules corresponding to the query and visualize them
	def apply_query(self):
		rules = self.gather_rules_gephi() if True else self.gather_rules() # TODO gephi
		#print("Got rules, starting filtering")

		# self.qargs.filter_bools can be empty list - meaning system boolean setting is in use
		if self.qargs.filter_bools != None:
			rules = data.filter_terules_boolean(rules, self.qargs.filter_bools)
		
		#filter out rules assigned to specified attributes
		if self.qargs.filter_attrs:
			rules = self.filter_attribute_rules(rules)

		#expand rules ending in attribute (not user specified side - soruce/target)
		if self.qargs.expand_attributes:
			rules = self.expand_rules(rules)

		#Rewrite rules to feature domain groups instead of types
		if self.qargs.domain_grouping:
			rules =self.rewrite_rules_grouping(rules)

		#Abort in case no rules were found
		if len(rules) == 0:
			print("No rules found!", file=sys.stderr)
			sys.exit()

		#gephi export TODO: rewrite as command line argument
		if True:
			export.export_package(self.main_group, self.package_attributes, rules)
			return

		#vusualize results
		if self.qargs.source_group or self.qargs.target_group:
			vis.visualise_rules(self.main_group.name.upper(), bool(self.qargs.source), 
										 rules, self.qargs.size_multiplier)
		else:
			#non-grouping
			vis.visualise_rules(self.qargs.main_domain, bool(self.qargs.source), 
								rules, self.qargs.size_multiplier)

	#get all rules corresponding to this query
	def gather_rules(self):
		rules = []
		if self.qargs.domain_grouping:
			#get domain grouping if the output should be grouped
			self.domain_grouping = grouping.group_types_cil()
			#reversal of domain grouping - for fast inverse search
			self.reverse_grouping = {}
			for group in self.domain_grouping.values():
				for _type in group.types:
					self.reverse_grouping[_type] = group#group.name.upper()
			#print("Got grouping, getting rules.")
			
			#get group containing specified source/target type 
			if self.qargs.source_group or self.qargs.target_group:
				self.main_group = self.reverse_grouping.get(self.qargs.main_domain)

				if not self.main_group:
					print("Error: Unknown type \"" + self.qargs.main_domain + "\"!", file=sys.stderr)
					sys.exit()

				#get all rules corresponding to source/target domain group
				print("Gathering rules for following types: ", end="", sep="")
				for type_ in sorted(self.main_group.types):
					print(type_, ", ", end="", sep="", flush=True)
					source = type_ if self.qargs.source else None
					target = type_ if self.qargs.target else None
					rules += data.get_type_enf_rules(ruletype = ["allow"],
												    source = source,
												    target = target, 
												    tclass = self.qargs.tclass,
													perms = self.qargs.perms,
													booleans = self.qargs.boolean
												    )
				print("\n")
		# source/target is single type
		if not (self.qargs.source_group or self.qargs.target_group):
			rules = data.get_type_enf_rules(ruletype = ["allow"],
							    source = self.qargs.source,
							    target = self.qargs.target, 
							    tclass = self.qargs.tclass,
								perms = self.qargs.perms,
								booleans = self.qargs.boolean
							    )
		return rules

	def gather_rules_gephi(self):
		rules = []
		
		self.domain_grouping = grouping.group_types_cil()
		#reversal of domain grouping - for fast inverse search
		self.reverse_grouping = {}
		for group in self.domain_grouping.values():
			for _type in group.types:
				self.reverse_grouping[_type] = group#group.name.upper()
		print("Got grouping, getting rules.")
		
		self.main_group = self.domain_grouping.get(self.qargs.main_domain)
		print(self.qargs.main_domain)
		package_types = set(self.main_group.types)

		package_attributes = set()
		#get all attributes corresponding to types in given package
		for t in package_types:
			package_attributes |= set(data.get_attributes_of_str(t))
		if self.qargs.filter_attrs:
			package_attributes -= set(self.qargs.filter_attrs) #TODO should there really be "-="?

		self.package_attributes = package_attributes

		all_rules = data.get_type_enf_rules(ruletype = ["allow"],
											    tclass = self.qargs.tclass,
												perms = self.qargs.perms,
												booleans = self.qargs.boolean
										    )
		# get only rules corresponding to given package
		for rule in all_rules:
			source = str(rule.source)
			if data.is_attribute(rule.source):
				if (source in package_attributes):
					rules.append(rule)
			elif (source in package_types):
				rules.append(rule)

			target = str(rule.target)
			if data.is_attribute(rule.target):
				if (target in package_attributes):
					rules.append(rule)
			elif (target in package_types):
				rules.append(rule)

		return rules

	def expand_rules(self, rules):
		expanded_rules = []
		other_side = "target" if self.qargs.source else "source"
		#attributes = data.get_attributes
		for rule in rules:
			if data.is_attribute(getattr(rule, other_side)):
				expanded_rules.extend(data.half_expand_rule(rule, not self.qargs.source))
			else:
				expanded_rules.append(rule)
		return expanded_rules

	def rewrite_rules_grouping(self, rules):
		results = []

		for rule in rules:
			if self.qargs.source:
				# Can be either one of [source_type, main_domain_group, attribute_of_source]
				source = self.main_group.name.upper() if self.qargs.source_group and \
														 (not data.is_attribute(rule.source)) \
													  else rule.source
				target = self.reverse_grouping.get(rule.target)
				#can be attribute -> won't be found in reverse_grouping
				target = target.name.upper() if target else rule.target
			else: #target is main
				target = self.main_group.name.upper() if self.qargs.target_group and \
														 (not data.is_attribute(rule.target)) \
													  else rule.target
				source = self.reverse_grouping.get(rule.source)
				#can be attribute -> won't be found in reverse_grouping
				source = source.name.upper() if source else rule.source

			results.append(data.make_expanded_rule(rule, source, target))
		return results


	def filter_attribute_rules(self, rules):
		# filter attribute rules
		filtered_rules = []
		
		if True: #TODO gephi
			for rule in rules:
				if (data.is_attribute(rule.source) and (str(rule.source) in self.qargs.filter_attrs)) or \
				   (data.is_attribute(rule.target) and (str(rule.target) in self.qargs.filter_attrs)):
					continue				
				filtered_rules.append(rule)

			return filtered_rules

		for rule in rules:
			attr = str(getattr(rule, "source" if self.qargs.source else "target"))

			#skip filtered attributes
			if attr in self.qargs.filter_attrs:
				continue
			filtered_rules.append(rule)
		return filtered_rules


	def apply_query_grouping(self, domain_grouping):
		#if self.qargs.source_group or self.qargs.target_group:

		main_group = None
		for group in domain_grouping.values():
			if group.contains(self.qargs.main_domain):
				main_group = group
				break
		else:
			pass # TODO: raise exception

		rules = []
		#get all rules corresponding to source/target domain group
		for type_ in main_group.types:
			source = type_ if self.qargs.source else None
			target = type_ if self.qargs.target else None
			rules += data.get_type_enf_rules(ruletype = ["allow"],
										    source = source,
										    target = target, 
										    tclass = self.qargs.tclass,
											perms = self.qargs.perms,
											booleans = self.qargs.boolean
										    )

		# filtering

		if self.qargs.filter_bools != None:
			rules = data.filter_terules_boolean(rules, self.qargs.filter_bools)

		#attribute containing "main domain"	
		main_domain = "source" if self.qargs.source else "target"

		# filter attribute rules
		filtered_rules = []
		if self.qargs.filter_attrs:
			for rule in rules:
				attr = str(getattr(rule, main_domain))

				#skip filtered attributes
				if attr in self.qargs.filter_attrs:
					continue
				filtered_rules.append(rule)
		else:
			filtered_rules = rules
		
		# expand rules ending in attribute
		if False:
			rules = []
			other_side = "target" if self.qargs.source else "source"
			#attributes = data.get_attributes
			for rule in filtered_rules:
				if data.is_attribute(getattr(rule, other_side)):
					rules.extend(data.half_expand_rule(rule, self.qargs.source))
				else:
					rules.append(rule)
			#apply_domain_grouping()

		else:
			rules = filtered_rules	

		rules =_rewrite_rules_grouping(rules, domain_grouping)

		#return QueryResults(self.qargs, rules)

		#vis.visualise_rules(self.qargs.main_domain, bool(self.qargs.source), rules)
		vis.visualise_rules_grouping(main_group, bool(self.qargs.source), rules)
		

#



class QueryResults:
	def __init__(self, args, rules):
		self.qargs = args
		self.rules = rules
		self.main_domain = args.main_domain
		self.main_is_source = bool(args.source)

		# User can specify only one of "source" and "target" of the query
		# Dteremine which one is set
		#if args.source:

		
		#self.main_domain = "source" if qargs.source else "target"
