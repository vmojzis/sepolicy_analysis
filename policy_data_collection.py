#!/usr/bin/env python
import selinux
import sepolicy   

import os, sys, inspect
# use this if you want to include modules from a subfolder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"setools_v4")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import setools

def expand_attr(attr):
    """Render type and role attributes."""
    items = "\n\t".join(sorted(str(i) for i in attr.expand()))
    contents = items if items else "<empty attribute>"
    return "{0}\n\t{1}".format(attr.statement(), contents)


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
	results = [x for x in q.results()]
	if results:
		return [str(x) for x in results[0].expand()]
	else :
		return []
	

#print "Attribute count: " + str(len(get_all_attributes()))
#print "Type count: " + str(sum(1 for _ in setools.SELinuxPolicy().types()))
#print get_types()
#print "\n".join(get_domain_types())



# setools.SELinuxPolicy().typeattributes()
