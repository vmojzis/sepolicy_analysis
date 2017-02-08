#!/usr/bin/env python3

import os
from setuptools import setup, find_packages

setup(
    name="SEPolicyAnalysis",
    version="0.1",
    packages=find_packages(exclude=["setools", "policy_data", "demo", "examples", "data"]),
    scripts=['extract_cil.sh', 'sebuild_graph', 'seexport_graph', 'segraph_query', 'sevisual_query'], #, 'export_graph.py', 'build_graph.py', 'visual_query.py', 'graph_query.py'
    #keep config files
    package_data={
    # If any package contains *.conf files, include them:
        '': ['*.conf']
    },
    data_files=[
            ("/etc/sepolicyanalysis/", ['sepolicyanalysis/domain_groups_cil.conf', 'sepolicyanalysis/security_related.conf'])
        ],
    # exclude 'readme' from all packages
    exclude_package_data={'': ['readme', 'readme.md']},
    author="Vit Mojzis",
    author_email="vmojzis@redhat.com",
    description="Tool designed to help increase the quality of SELinux policy by identifying possibly dangerous permission pathways, simplifying regression testing and providing policy visualization.",
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)'
        ],
    keywords="SELinux policy analysis visualization security",
    url="https://github.com/vmojzis/sepolicy_analysis"   # github repository - wiki pages serve as documentation
)