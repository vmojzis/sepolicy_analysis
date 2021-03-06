#!/usr/bin/env python3

# (C) Copyright 2016 Vit Mojzis, vmojzis@redhat.com
# 
# This program is distributed under the terms of the GNU General Public License
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
from setuptools import setup, find_packages
import distutils.command.install_data
import re

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(fname).read()

#custom install_data to fix man page extensions (to fit Fedora)
#based on https://bugs.python.org/issue644744
class MyInstallData (distutils.command.install_data.install_data):
    """My own data installer to handle .man pages"""
    def copy_file (self, filename, dirname):
        (out, _) = distutils.command.install_data.install_data.copy_file(self, filename, dirname)
        # match for man pages
        if re.search(r'/man/man\d/.+\.\d$', out):
            return (out+".*", _)
        return (out, _)

setup(
    cmdclass = { 'install_data': MyInstallData },
    name="sepolicy_analysis",
    version="0.1",
    packages=find_packages(exclude=["setools", "policy_data", "demo", "examples", "data"]),
    scripts=['seextract_cil', 'sebuild_graph', 'seexport_graph', 'segraph_query', 'sevisual_query'], #, 'export_graph.py', 'build_graph.py', 'visual_query.py', 'graph_query.py'
    #replaced by MANIFEST.in
    package_data={
    # If any package contains *.conf files, include them:
        #'': ['*.conf', 'sepolicyanalysis/doc/*.1'],
        #'sepolicyanalysis/doc' : ['man/*.1']
    },
    data_files=[
            ("/etc/sepolicyanalysis/", ['sepolicyanalysis/domain_groups_cil.conf', 'sepolicyanalysis/security_related.conf']),
            ("/usr/share/man/man1/", ['sepolicyanalysis/doc/sebuild_graph.1', 'sepolicyanalysis/doc/seexport_graph.1', 'sepolicyanalysis/doc/seextract_cil.1', 'sepolicyanalysis/doc/segraph_query.1', 'sepolicyanalysis/doc/sevisual_query.1'])
        ],
    # exclude 'readme' from all packages
    #exclude_package_data={'': ['readme.md']},
    author="Vit Mojzis",
    author_email="vmojzis@redhat.com",
    description="SELinux policy analysis tool",
    #long_description=read('readme'),
    #long_description="Tool designed to help increase the quality of SELinux \
    #                  policy by identifying possibly dangerous permission \
    #                  pathways, simplifying regression testing and providing \
    #                  policy visualization",
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)'
        ],
    license="GPLv3",
    keywords="SELinux policy analysis visualization security",
    url="https://github.com/vmojzis/sepolicy_analysis"   # github repository - wiki pages serve as documentation
)
