Name:           SEPolicyAnalysis
Version:        0.1
Release:        1%{?dist}
Summary:        SELinux policy analysis tool

License:        GPLv3
URL:            https://github.com/vmojzis/sepolicy_analysis
Source0:        https://github.com/vmojzis/sepolicy_analysis/releases/download/%{version}/%{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3-devel

Requires: setools-python3 >= 4.0

%description
Tool designed to help increase the quality of SELinux policy by identifying
possibly dangerous permission pathways, simplifying regression testing and
providing policy visualization.

%prep
%autosetup
# Github prepends repository name to source folder name when aouto-creating source package
# % autosetup -n sepolicy_analysis-% {name}-% {version}

%build
%py3_build

%install
#mkdir -p % {buildroot}% {_mandir}/man1
%py3_install

%check
%if %{?_with_check:1}%{!?_with_check:0}
%{__python3} setup.py test
%endif

%files
%license COPYING
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

