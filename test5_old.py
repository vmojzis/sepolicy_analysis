#!/usr/bin/env python
import selinux
import sepolicy   
import setools
import sys
import copy
import subprocess

def expand_attr(attr):
    """Render type and role attributes."""
    items = "\n\t".join(sorted(str(i) for i in attr.expand()))
    contents = items if items else "<empty attribute>"
    return "{0}\n\t{1}".format(attr.statement(), contents)

q = setools.TypeAttributeQuery(setools.SELinuxPolicy())
q.name = ""
results = q.results()
for item in results:
	print item