#!/usr/bin/env python
import policy_data_collection as data
import sys
import visualization as vis
import config_loading as config

#print data.get_attributes_of("init_t")
#print "\n".join(sorted([str(x) for x in data.get_type_enf_rules(["allow"], "mozilla_plugin_t")]))


#Domain grouping
#./domain_grouping.py
# group_name >>
#    group_subjects (process labels)
#    group_objects (static data labels)

#Type enforcement rule gathering
#no filtering
#print "\n".join([str(x) for x in data.get_type_enf_rules(["allow"], "mozilla_plugin_t", _tclass = ["shm"])])
#rule filtering based on system boolean settings - "unconfined_mozilla_plugin_transition"
#print "\n".join([str(x) for x in data.filter_terules_boolean(data.get_type_enf_rules(["allow"], "mozilla_plugin_t", _tclass = ["shm"]))])
#rule filtering based on "bool_config" file
#print "\n".join([str(x) for x in data.filter_terules_boolean(data.get_type_enf_rules(["allow"], "mozilla_plugin_t", _tclass = ["shm"]), config.get_boolean_config())])

#visualization (visualization.py) - output in "path.pdf"
#vis.foo()
#vis.apply_query({'main_domain':'rdisc_t'})
#data.get_types_of()
print type(data.get_attributes_of_("init_t")[0])