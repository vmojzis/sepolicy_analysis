#!/usr/bin/env python
import selinux
import sepolicy   

// ?all? allow rules
//sepolicy.search(['allow'])

//all types
//sepolicy.info(0)
print sepolicy.info(sepolicy.TYPE)

//get all entrypoints
//sepolicy.info(sepolicy.ATTRIBUTE, "entry_type")

//for domain_type in self.ptypes:
//            self.attributes[domain_type] = sepolicy.info(sepolicy.TYPE, ("%s") % domain_type)[0]["attributes"]

