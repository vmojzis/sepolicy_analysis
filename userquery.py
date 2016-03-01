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
import math

class UserQuery:
	""" SETools policy query """
	#query arguments (object returned by argparser)
	#qargs = None
	def __init__(self, args):
		self.qargs = args


	# query - argparser output
	#TODO - specify the query and write command line argument reading
	def apply_query(self):
						   
		rules = data.get_type_enf_rules(_ruletype = ["allow"],
									    _source = self.qargs.source,
									    _target = self.qargs.target, 
									    _tclass = self.qargs.tclass,
										_perms = self.qargs.perms,
										_booleans = self.qargs.boolean
									    )

		# filtering																																																																																																																																																																																											)

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

		
		# expand rules ending in attribute
		if False:
			rules = []
			other_side = "target" if self.qargs.source else "source"
			attributes = data.get_attributes
			for rule in filtered_rules:
				if data.is_attribute(getattr(rule, other_side)):
					rules.extend(data.half_expand_rule(rule, self.qargs.source))
				else:
					rules.append(rule)
			#apply_domain_grouping()

		else:
			rules = filtered_rules	

		#return QueryResults(self.qargs, rules)

		vis.visualise_rules(self.qargs.main_domain, bool(self.qargs.source), rules)


	def apply_query_grouping(self, domain_grouping):

		for group in domain_grouping.values():
			if group.contains(self.qargs.main_domain):
				main_group = group
				break
		else:
			pass # TODO: raise exception

		rules = []
		for type_ in group.types:
			if type_ == "racoon_t":
				continue
			rules += data.get_type_enf_rules(_ruletype = ["allow"],
										    _source = self.qargs.source,
										    _target = self.qargs.target, 
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
			attributes = data.get_attributes
			for rule in filtered_rules:
				if data.is_attribute(getattr(rule, other_side)):
					rules.extend(data.half_expand_rule(rule, self.qargs.source))
				else:
					rules.append(rule)
			#apply_domain_grouping()

		else:
			rules = filtered_rules	

		#return QueryResults(self.qargs, rules)

		vis.visualise_rules(self.qargs.main_domain, bool(self.qargs.source), rules)

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