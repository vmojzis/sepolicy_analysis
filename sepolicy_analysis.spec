Name:           sepolicy_analysis
Version:        0.1
Release:        2%{?dist}
Summary:        SELinux policy analysis tool

License:        GPLv3
URL:            https://github.com/vmojzis/sepolicy_analysis
#./setup.py egg_info --egg-base /tmp sdist
Source0:        https://github.com/vmojzis/sepolicy_analysis/releases/download/%{version}/%{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3-devel

Requires: python3-setools >= 4.0
Requires: python3-networkx >= 1.11
Requires: python3-matplotlib

%description
Tool designed to help increase the quality of SELinux policy by identifying
possibly dangerous permission pathways, simplifying regression testing and
providing policy visualization.

%prep
%autosetup

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
%dir %{_sysconfdir}/sepolicyanalysis
%config(noreplace) %{_sysconfdir}/sepolicyanalysis/domain_groups_cil.conf
%config(noreplace) %{_sysconfdir}/sepolicyanalysis/security_related.conf
%doc %{_mandir}/man1/se*

%changelog
* Mon May 15 2017 Vit Mojzis <vmojzis@redhat.com> - 0.1-1
- Add dependency on python3-networkx

* Wed Feb 08 2017 Vit Mojzis <vmojzis@redhat.com> - 0.1-1
- Initial release

