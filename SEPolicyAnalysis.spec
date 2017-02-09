%global srcname SEPolicyAnalysis
%global sum SELinux policy analysis tool

Name:           SEPolicyAnalysis
Version:        0.1
Release:        1%{?dist}
Summary:        %{sum}

License:        GPLv3
URL:            https://github.com/vmojzis/sepolicy_analysis
Source0:        %{srcname}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3-devel

Requires: setools >= 4.0

%description
Tool designed to help increase the quality of SELinux policy by identifying
possibly dangerous permission pathways, simplifying regression testing and
providing policy visualization.

%prep
%autosetup

%build
%py3_build

%install
#mkdir -p % {buildroot}% {_bindir}
mkdir -p %{buildroot}%{_mandir}/man1
%py3_install

%check
#% {__python3} setup.py test

# Note that there is no %%files section for the unversioned python module if we are building for several python runtimes
%files
#% license COPYING
# readme
%{python3_sitelib}/*
%{_bindir}/seextract_cil
%{_bindir}/sebuild_graph
%{_bindir}/seexport_graph
%{_bindir}/segraph_query
%{_bindir}/sevisual_query
%config(noreplace) %{_sysconfdir}/sepolicyanalysis/domain_groups_cil.conf
%config(noreplace) %{_sysconfdir}/sepolicyanalysis/security_related.conf
%doc %{_mandir}/man1/se*

%changelog
* Wed Feb 08 2017 Vit Mojzis <vmojzis@redhat.com> - 0.1-1
- Initial release

