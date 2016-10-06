# SELinux Policy Analysis Tool

[![License](https://img.shields.io/github/license/dkopecek/usbguard.svg)](https://github.com/vmojzis/sepolicy_analysis/blob/master/COPYING.txt)

This repository contains tool designed to help increase the quality of SELinux policy by identifying possibly dangerous permission pathways, simplifying regression testing and evaluating CVE (Common Vulnerabilities and Exposures).

## About
Due to practical reasons SELinux policy (type enforcement) does not adhere to any formal model that would ensure complete security of target system. This means that security issues can be present and their existence goes unseen unless someone manages to exploit them. Such issues can be caused by:
* Overly relaxed policy modules
* Unintended side effects of attribute/macro use
* Unforeseen module interactions

Encapsulation and interdependence of policy statements together with policy size make manual analysis difficult and extremely time consuming. This project aims at automation of policy analysis leading to simplification of proactive security approach.

***

## Use Cases
### Automated search for specified permission pathways (potential security issues)

Permission pathways (given combinations of permissions between multiple SELinux types) corresponding to potentially harmful actions in the system are found and reported to the user. Even very specific queries (focusing on given type) can be entered which can serve as (potentially more complex) "neverallow" rules.


    Build graph file derived from SELinux policy (active policy is used by default):
    $ ./build_graph.py -fb -c file,process output/graph
    Search for potential security issues (query function names and descriptions can be found in graph_query_functions.py):
    $ ./graph_query.py output/graph transition_write

### Regression testing
The tool makes it easy to compare query results between different policy versions. This feature ensures that recent changes (bug fixing, new policy modules, etc.) aren't decreasing security of the policy. Compared to "sediff", only relevant results are shown (potential security issues) and the process is more resource effective (especially memory usage).

    Build second graph file based on different policy version:
    $ ./build_graph.py -fb -c file,process output/graph2 -p policy_data/policy.30
    Search for newly introduced issues (first graph is used as a baseline):
    $ ./graph_query.py output/graph2 -d output/graph transition_write

### CVE evaluation (work in progress)
The tool could be used to evaluate feasibility of exploiting *common vulnerabilities and exposures* (CVE) on systems protected by SELinux. This could help pinpoint cases where SELinux can be used to prevent the attack and therefore expedite removal of the threat (temporary policy module can be shipped and applied significantly faster than new package version).

### Visualisation (work in progress)
Understanding policy statements can be difficult because of the use of macros and attributes. Now it's possible to visualise policy section (given module or type) in a way that requires only basic understanding of mandatory access control (type enforcement). This feature is aimed at new policy writers and package maintainers who know what access permissions are necessary, but don't have deep understanding of SELinux. Visualisation of more complex policy modules can aid more skilled policy writers with bug fixing and module integration. 

    Switch to "visualization" branch:
    $git checkout visualization
    Generate "graphml" file containing policy concerning selected module:
    $./visual_query.py -s <policy_module> -fb
    Open in [Gephi](https://gephi.org/) and change colours of nodes (attributes/types/types from selected package) and edges (attribute assignments/access vectors) based on their type. Edge labels contain permissions (or permission sets) concerning adjacent nodes.

***

## Quick Links
[comment]: <>https://docs.google.com/a/redhat.com/presentation/d/14DcfzxbX9P0jqMtEeEe7fcj_iKlbn464YjVO5zYP1Ac/editusp=sharing) 
 [Roadmap / Development](https://github.com/vmojzis/sepolicy_analysis/wiki/Roadmap) | [Contact](mailto:vmojzis@redhat.com) | [Installation](https://github.com/vmojzis/sepolicy_analysis/wiki/Installation) |
 :---: | :---: | :---: |
Road map of planned features and modules currently in development. | For bugs or new query function ideas please create [github issue](https://github.com/vmojzis/sepolicy_analysis/issues). Simple patches can be sent by email or pull request. Questions are welcome on [vmojzis@redhat.com](mailto:vmojzis@redhat.com) | Dependencies and setup procedure | 