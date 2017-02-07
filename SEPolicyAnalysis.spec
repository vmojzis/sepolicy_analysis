%global srcname SEPolicyAnalysis
%global sum SELinux policy analysis tool

Name:           python-%{srcname}
Version:        0.1
Release:        1%{?dist}
Summary:        %{sum}

License:        GPL-3.0
URL:            https://github.com/vmojzis/sepolicy_analysis
Source0:        https://files.pythonhosted.org/packages/source/e/%{srcname}/%{srcname}-%{version}.tar.gz

BuildArch:      noarch


Provides: /bin/sebuild_graph
Provides: /bin/seexport_graph
Provides: /bin/segraph_query
Provides: /bin/sevisual_query

BuildRequires:  python3-devel

#Requires: setools >= 4.0

%description
Tool designed to help increase the quality of SELinux policy by identifying possibly dangerous permission pathways, simplifying regression testing and providing policy visualization.

%package -n python3-%{srcname}
Summary:        %{sum}
%{?python_provide:%python_provide python3-%{srcname}}

%description -n python3-%{srcname}
Tool designed to help increase the quality of SELinux policy by identifying possibly dangerous permission pathways, simplifying regression testing and providing policy visualization.

%prep
%autosetup -n %{srcname}-%{version}

%build
%py3_build

%install
mkdir -p %{buildroot}%{_bindir}
%py3_install

%check
#%{__python3} setup.py test

# Note that there is no %%files section for the unversioned python module if we are building for several python runtimes
%files -n python3-%{srcname}
#%license COPYING
#%doc readme
%{python3_sitelib}/*
%{_bindir}/extract_cil.sh
%{_bindir}/sebuild_graph
%{_bindir}/seexport_graph
%{_bindir}/segraph_query
%{_bindir}/sevisual_query
%config(noreplace) %{_sysconfdir}/sepolicyanalysis/domain_groups_cil.conf
%config(noreplace) %{_sysconfdir}/sepolicyanalysis/security_related.conf

%changelog