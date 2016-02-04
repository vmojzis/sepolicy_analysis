#!/usr/bin/env python

#egg_path='/home/vmojzis/DEVEL/selinux-policy/sepolicy_analysis/networkx-1.10-py3.4.egg'

#sys.path.append(egg_path)
import networkx as nx
import matplotlib.pyplot as plt

import selinux
import sepolicy   


# ?all? allow rules
#sepolicy.search(['allow'])

#all types
#sepolicy.info(0)
#print sepolicy.info(sepolicy.TYPE)

#get all entrypoints
#sepolicy.info(sepolicy.ATTRIBUTE, "entry_type")

#for domain_type in self.ptypes:
#            self.attributes[domain_type] = sepolicy.info(sepolicy.TYPE, ("%s") % domain_type)[0]["attributes"]

print sepolicy.info(sepolicy.ATTRIBUTE, "file_type")