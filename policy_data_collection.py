#!/usr/bin/env python
import selinux
import sepolicy  

import os, sys, inspect
# use this if you want to include modules from a subfolder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"setools")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import setools
#import setools.policyrep

def expand_attr(attr):
    """Render type and role attributes."""
    items = "\n\t".join(sorted(str(i) for i in attr.expand()))
    contents = items if items else "<empty attribute>"
    return "{0}\n\t{1}".format(attr.statement(), contents)

# half of BaseTERule.expand() method (expand only one side)
# expand_source - True means we want to expand source (target otherwise)
def half_expand_rule(rule, expand_source):
	results = []
	expansion = rule.source.expand() if expand_source else rule.target.expand()
	if expand_source:
		for t in expansion:
			results.append(setools.policyrep.terule.expanded_te_rule_factory(rule, t, rule.target))
	else:
		for t in expansion:
			results.append(setools.policyrep.terule.expanded_te_rule_factory(rule, rule.source, t))
	return results

#print type(list(results)[0])
#for item in results:
	#print expand_attr(item)
#	print item

# returns list of all attributes corresponding to given name
# seinfo -a[name]
def get_attributes_filter_name(name):
	q = setools.TypeAttributeQuery(setools.SELinuxPolicy())
	q.name = name
	results = q.results()
	return [str(x) for x in results]

# returns list of all attributes in loaded policy
# seinfo -a
def get_attributes():
	results = setools.SELinuxPolicy().typeattributes()
	return [str(x) for x in results]

# returns list of all types in loaded policy
# seinfo -t
def get_types():
	results = setools.SELinuxPolicy().types()
	return [str(x) for x in results]

# returns list of types with "domain" attribute
def get_domain_types():
	q = setools.TypeAttributeQuery(setools.SELinuxPolicy())
	q.name = "domain"
	results = next(q.results()) #should contain only 1 item - TypeAttribute("domain")
	if results:
		return [str(x) for x in results.expand()]
	else :
		return []
	
# returns attributes of given type
def get_attributes_of(type):
	return [str(x) for x in type.expand()]

# returns attributes of given type
def get_attributes_of_str(type_name):
	q = setools.TypeQuery(setools.SELinuxPolicy())
	q.name = type_name
	results = []
	for item in q.results():
		# return attributes of all types corresponding to given name
		results.extend([str(x) for x in item.attributes()]) 
	return results


# returns types that have given attribute (specified by name)
def get_types_of_str(attr_name):
	q = setools.TypeAttributeQuery(setools.SELinuxPolicy())
	q.name = attr_name
	results = q.results().next() #should contain only 1 item - TypeAttribute("domain")
	if results:
		return [str(x) for x in results.expand()]
	else :
		return []

# returns types that have given attribute
def get_types_of(attr):
	return [str(x) for x in attr.expand()]

# Get type enforcement rules (same behaviour as sesearch) 
# ruletype -> list containing [allow, auditallow, dontaudit, type_transition, type_change, type_member]+
# source -> source type/attribute
# source_indirect -> "-ds" parameter of sesearch
# tclass -> list of target classes (rules containing at least one of the classes)
# perms -> list of permissions (rules containing at least one of the permissions)
# booleans -> list of booleans
# returns generator for TERule objects
def get_type_enf_rules(_ruletype = ["allow"],
					   _source = None, 
					   _target = None, 
					   _tclass = None, 
					   _perms = None, 
					   _booleans = None, 
					   _source_indirect = True, 
					   _target_indirect = True):

	try:
		q = setools.TERuleQuery(setools.SELinuxPolicy(),
	                            ruletype=_ruletype,
	                            source=_source,
	                            source_indirect=_source_indirect,
	                            target=_target,
	                            target_indirect=_target_indirect,
	                            tclass = _tclass,
	                            perms = _perms,
	                            boolean = _booleans)
		#return [str(x) for x in q.results()]

		# rule.conditional_block meaning (guessing):
		#   if rule.conditional_block == True: rule is applied if the boolean is set to True
		# 	if rule.conditional_block == False: rule is applied if the boolean is set to False

		return [x for x in q.results()]
	except ValueError:
		return []

# filter type enforcement rules based on boolean setting
# rules -> generator for TERule list
# bool_state -> dictionary of booleans and their states - default is current boolean status
def filter_terules_boolean(rules, bool_state = None):
	results = []
	for rule in rules:
		try:
			boolean = str(rule.conditional)
			# get boolean setting (provided by "bool_state" dictionary, or get current value from active policy)
			state = bool_state.get(boolean, selinux.security_get_boolean_active(boolean)) \
					if bool_state else selinux.security_get_boolean_active(boolean)
 
			if rule.conditional_block == state:
				# return rules in agreement with boolean settings
				results.append(rule)
			#else:
			#	print("Rule removed")

		except setools.policyrep.exception.RuleNotConditional:
			# return all unconditional rules
			results.append(rule)

	return results


# returns dictionary of all booleans and their current values
def get_booleans():
	#TODO: determine boolean values based on user*defined config file
	bools = {}
	# boolean.state contains default setting of the boolean
	for boolean in setools.SELinuxPolicy().bools():
		# get current setting of given boolean
		bools[str(boolean)] = selinux.security_get_boolean_active(str(boolean)) == 1
	return bools

# is given type enforcement rule conditional?
def is_conditional(rule):
	try:
		if type(rule) in [setools.policyrep.terule.ExpandedTERule, setools.policyrep.terule.ExpandedAVRule] :
			boolean = str(rule.origin.conditional)
		else:
			boolean = str(rule.conditional)
		return boolean

	except setools.policyrep.exception.RuleNotConditional:
		False

# is given object of type "TypeAttribute"
def is_attribute(obj):
	return isinstance(obj, setools.policyrep.typeattr.TypeAttribute)


# return expanded te rule
def make_expanded_rule(original_rule, source, target):
	return setools.policyrep.terule.expanded_te_rule_factory(original_rule, source, target)


#print "Attribute count: " + str(len(get_all_attributes()))
#print "Type count: " + str(sum(1 for _ in setools.SELinuxPolicy().types()))
#print get_types()
#print "\n".join(get_domain_types())



# setools.SELinuxPolicy().typeattributes()
