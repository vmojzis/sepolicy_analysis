#!/usr/bin/env python
import policy_data_collection as data
import sys
import visualization as vis
import visualization_setools_3 as vis3
import config_loading as config

#print data.get_attributes_of("domain")
#print("\n".join(sorted(data.get_type_enf_rules(["allow"], sys.argv[1]))))
#print("\n".join(sorted(data.get_type_enf_rules(["allow"], sys.argv[1]))))
#print [str(x) for x in data.get_type_enf_rules(["allow"], sys.argv[1])]
#print "\n".join([str(x) for x in data.filter_terules_boolean(data.get_type_enf_rules(["allow"], "mozilla_plugin_t", _tclass = ["shm"]))])
#data.get_booleans()

vis.foo()
#vis3.foo()

#print config.get_boolean_config()