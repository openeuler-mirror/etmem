%global debug_package %{nil}

Name:	       etmem
Version:       1.1
Release:       1
Summary:       etmem 
License:       MulanPSL-2.0
URL:           https://gitee.com/openeuler/etmem
Source0:       https://gitee.com/openeuler/etmem/repository/archive/%{version}.tar.gz

#Dependency
BuildRequires: cmake gcc gcc-c++ glib2-devel
BuildRequires: libboundscheck numactl-devel libcap-devel json-c-devel
Requires: libboundscheck json-c libcap numactl-libs
Requires: glib2

%description
etmem module

#Build sections
%prep
%autosetup -n etmem-%{version} -p1

%build
mkdir -p build
cd build
cmake .. 
make

%install
mkdir -p $RPM_BUILD_ROOT%{_bindir}
mkdir -p $RPM_BUILD_ROOT%{_libdir}
mkdir -p $RPM_BUILD_ROOT%{_includedir}
install -d $RPM_BUILD_ROOT%{_sysconfdir}/etmem/

install -m 0700 etmem/build/bin/etmem $RPM_BUILD_ROOT%{_bindir}
install -m 0700 etmem/build/bin/etmemd $RPM_BUILD_ROOT%{_bindir}
install -m 0600 etmem/conf/damon_conf.yaml $RPM_BUILD_ROOT%{_sysconfdir}/etmem/
install -m 0600 etmem/conf/cslide_conf.yaml $RPM_BUILD_ROOT%{_sysconfdir}/etmem/
install -m 0600 etmem/conf/slide_conf.yaml $RPM_BUILD_ROOT%{_sysconfdir}/etmem/
install -m 0600 etmem/conf/thirdparty_conf.yaml $RPM_BUILD_ROOT%{_sysconfdir}/etmem/

install -m 0750 build/memRouter/memdcd $RPM_BUILD_ROOT%{_bindir}
install -m 0750 build/userswap/libuswap.a $RPM_BUILD_ROOT%{_libdir}
install -m 0644 userswap/include/uswap_api.h $RPM_BUILD_ROOT%{_includedir}
%files
%defattr(-,root,root,0750)
%attr(0500, -, -) %{_bindir}/etmem
%attr(0500, -, -) %{_bindir}/etmemd
%dir %{_sysconfdir}/etmem
%{_sysconfdir}/etmem/damon_conf.yaml
%{_sysconfdir}/etmem/cslide_conf.yaml
%{_sysconfdir}/etmem/slide_conf.yaml
%{_sysconfdir}/etmem/thirdparty_conf.yaml
%attr(0550, -, -) %{_bindir}/memdcd
%attr(0550, -, -) %{_libdir}/libuswap.a
%{_includedir}/uswap_api.h

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%changelog
* Sun Jan 29 2023 liubo <liubo254@huawei.com> 1.1-1
- upgrade etmem version to 1.1

* Thu Dec 1 2022 liubo <liubo254@huawei.com> 1.0-12
- Modify License to MulanPSL-2.0 in the spec

* Mon Aug 1 2022 liubo <liubo254@huawei.com> 1.0-11
- Sync the features and bug fixes in the etmem source repo. 

* Thu Dec 16 2021 YangXin <245051644@qq.com> 1.0-10
- Update memdcd engine for userswap page filter.

* Fri Oct 29 2021 liubo <liubo254@huawei.com> 1.0-9
- Add missing URL and source to etmem.spec

* Tue Oct 19 2021 shikemeng <shikemeng@huawei.com> 1.0-8
- Add missing Requires
- Remove write permssion in %file after strip
- Change Requires numactl to numactl-libs

* Thu Sep 30 2021 yangxin <245051644@qq.com> 1.0-7
- Update etmem and add new features memRouter and userswap.=

* Mon Aug 2 2021 louhongxiang <louhongxiang@huawei.com> 1.0-6
- cancel write permission of root.

* Mon May 24 2021 liubo <liubo254@huawei.com> 1.0-5
- add missing BuildRequires in etmem spec

* Fri Apr 2 2021 louhongxiang <louhongxiang@huawei.com> 1.0-4
- modify README correctly

* Sat Mar 20 2021 liubo <liubo254@huawei.com> 1.0-3
- Change aarch64 march to armv8-a

* Thu Mar 18 2021 liubo <liubo254@huawei.com> 1.0-2
- Fix 64K pagesize scan problem

* Thu Mar 18 2021 louhongxiang <louhongxiang@huawei.com>
- Package init
