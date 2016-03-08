#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
import visualization as vis
import domain_grouping as grouping
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
		rules = self.gather_rules()
		print("Got rules, starting filtering")

		# self.qargs.filter_bools can be empty list - meaning system boolean setting is in use
		if self.qargs.filter_bools != None:
			rules = data.filter_terules_boolean(rules, self.qargs.filter_bools)
		
		#filter out rules assigned to specified attributes
		if self.qargs.filter_attrs:
			rules = self.filter_attribute_rules(rules)

		#expand rules ending in attribute (not user specified side - soruce/target)
		if self.qargs.expand_attributes:
			rules = self.expand_rules(rules)

		#visualize
		if self.qargs.domain_grouping:
			rules =self.rewrite_rules_grouping(rules)


		if self.qargs.source_group or self.qargs.target_group:
			vis.visualise_rules_grouping(self.main_group, bool(self.qargs.source), rules)
		else:
			#non-grouping
			vis.visualise_rules(self.qargs.main_domain, bool(self.qargs.source), rules)

	#get all rules corresponding to this query
	def gather_rules(self):
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
				rules = []
				for type_ in self.main_group.types:
					print("Getting rules for: ", type_)
					source = type_ if self.qargs.source else None
					target = type_ if self.qargs.target else None
					rules += data.get_type_enf_rules(_ruletype = ["allow"],
												    _source = source,
												    _target = target, 
												    _tclass = self.qargs.tclass,
													_perms = self.qargs.perms,
													_booleans = self.qargs.boolean
												    )
		# source/target is single type
		if not (self.qargs.source_group or self.qargs.target_group):
			rules = data.get_type_enf_rules(_ruletype = ["allow"],
							    _source = self.qargs.source,
							    _target = self.qargs.target, 
							    _tclass = self.qargs.tclass,
								_perms = self.qargs.perms,
								_booleans = self.qargs.boolean
							    )
		return rules

	def expand_rules(rules):
		expanded_rules = []
		other_side = "target" if self.qargs.source else "source"
		#attributes = data.get_attributes
		for rule in rules:
			if data.is_attribute(getattr(rule, other_side)):
				expanded_rules.extend(data.half_expand_rule(rule, self.qargs.source))
			else:
				expanded_rules.append(rule)
		expanded_rules

	def rewrite_rules_grouping(self, rules):
		results = []

		for rule in rules:
			if self.qargs.source:
				# Can be either one of [source_type, main_domain_group, attribute_of_source]
				source = self.main_group.name.upper() if self.qargs.source_group and \
														 not data.is_attribute(rule.source) \
													  else rule.source
				target = self.reverse_grouping.get(rule.target)
				#can be attribute -> won't be found in reverse_grouping
				target = target.name.upper() if target else rule.target
			else: #target is main
				target = self.main_group.name.upper() if self.qargs.target_group and \
														 not data.is_attribute(rule.target) \
													  else rule.target
				source = self.reverse_grouping.get(rule.source)
				#can be attribute -> won't be found in reverse_grouping
				source = source.name.upper() if source else rule.source

			results.append(data.make_expanded_rule(rule, source, target))
		return results


	def filter_attribute_rules(rules):
		# filter attribute rules
		filtered_rules = []
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
			rules += data.get_type_enf_rules(_ruletype = ["allow"],
										    _source = source,
										    _target = target, 
										    _tclass = self.qargs.tclass,
											_perms = self.qargs.perms,
											_booleans = self.qargs.boolean
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