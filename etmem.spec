%global debug_package %{nil}

Name:	       etmem
Version:       1.0
Release:       12
Summary:       etmem 
License:       MulanPSL-2.0
URL:           https://gitee.com/openeuler/etmem
Source0:       https://gitee.com/openeuler/etmem/repository/archive/%{version}.tar.gz

Patch0: 0001-fix-64K-pagesize-scan-problem.patch
Patch1: 0002-change-aarch64-march-to-armv8-a.patch
Patch2: 0003-update-README.md.patch
Patch3: 0004-add-cslide-for-etmem.patch
Patch4: 0005-fix-code-check-problems.patch
Patch5: 0006-remove-unused-share-vmas-merge.patch
Patch6: 0007-fix-error-when-open-idle_pages-failed.patch
Patch7: 0008-fix-memleak.patch
Patch8: 0009-fix-some-bugs-that-occur-when-execute-obj-add-or-del.patch
Patch9: 0010-clean-code.patch
Patch10: 0011-wait-for-next-period-when-error-occurs-in-this-perio.patch
Patch11: 0012-add-recursive-in-etmemd_get_task_pids.patch
Patch12: 0013-check-permission-according-cmd-to-be-executed.patch
Patch13: 0014-stat-pages-info-early-only-replace-cold-mem-in-hot-nodes.patch
Patch14: 0015-limit-mig_quota-hot_reserve-to-0-INT_MAX.patch
Patch15: 0016-add-some-dfx-info.patch
Patch16: 0017-do-not-stop-the-process-when-failed-to-delete-any-obj.patch
Patch17: 0018-fix-code-check-warnning.patch
Patch18: 0019-accept-review-advise.patch
Patch19: 0020-revert-socket-permission-check.patch
Patch20: 0021-add-thirdpart-engine.patch
Patch21: 0022-export-symbols-for-user-defined-thirdparty-engine.patch
Patch22: 0023-accept-review-advise.patch
Patch23: 0024-correct-etmemd-name.patch
Patch24: 0025-add-support-for-systemctl-mode-to-start-etmem.patch
Patch25: 0026-add-scan-library.patch
Patch26: 0027-add-ign_host-to-ignore-host-access-when-scan-vm.patch
Patch27: 0028-openlog-with-same-ident.patch
Patch28: 0029-accept-advise.patch
Patch29: 0030-notify-rpc-success-with-finish-tag.patch
Patch30: 0031-remove-node_watermark.patch
Patch31: 0032-print-all-log-to-stdout.patch
Patch32: 0033-accept-review-advise.patch
Patch33: 0034-fix-open-swap_pages-failure.patch
Patch34: 0035-give-the-correct-example-of-config-file.patch
Patch35: 0036-check-if-start_task-is-NULL-before-call-it.patch
Patch36: 0037-correct-max_threads-when-max_threads-is-0.patch
Patch37: 0038-fix-etmem-help-return-error.patch
Patch38: 0039-check-if-eng_mgt_func-is-NULL-before-use-it.patch
Patch39: 0040-make-code-clean-for-etmem.patch
Patch40: 0041-return-error-if-migrate-failed-and-clean-code.patch
Patch41: 0042-etmemd-fix-memleak-and-clean-code.patch
Patch42: 0043-update-README.md.patch
Patch43: 0044-etmem-cleancode.patch
Patch44: 0045-add-dram_percent-to-etmem.patch
Patch45: 0046-Fix-memory-leak-in-slide-engine.patch
Patch46: 0047-move-all-the-files-to-sub-directory-of-etmem.patch
Patch47: 0048-Commit-new-features-memRouter-and-userswap-to-etmem.patch
Patch48: 0049-Add-engine-memdcd-to-etmemd.patch
Patch49: 0050-Add-CMakeLists.txt-for-three-features-of-etmem.patch
Patch50: 0051-update-memdcd-engine-for-userswap.patch
Patch51: 0052-etmem-correct-example-config-file.patch
Patch52: 0053-etmem-split-example_conf.yaml.patch
Patch53: 0054-add-License-in-memRouter.patch
Patch54: 0055-add-code-of-testcase-for-etmem-common-function.patch
Patch55: 0056-add-code-of-testcase-for-etmem-project-function.patch
Patch56: 0057-add-test-for-export-scan.patch
Patch57: 0058-add-code-of-testcase-for-etmem-common-function.patch
Patch58: 0059-add-code-of-testcase-for-etmem-log-ops.patch
Patch59: 0060-add-make-install-support-to-CMakeList.patch
Patch60: 0061-add-region-scan.patch
Patch61: 0062-fix-etmem-build-problem.patch
Patch62: 0063-etmem-add-code-of-testcase.patch
Patch63: 0064-etmem-add-code-of-testcase.patch
Patch64: 0065-etmem-add-code-of-testcase.patch
Patch65: 0066-etmem-add-sysmem_threshold-and-swap_threshold-parame.patch
Patch66: 0067-etmem-add-swapcache-reclaim-to-etmem.patch
Patch67: 0068-etmem-add-swap-flag-to-support-specified-page-swap-o.patch
Patch68: 0069-etmem-fix-the-swapcache-wmark-configuration-parse-er.patch
Patch69: 0070-etmem-update-README.md.patch
Patch70: 0071-etmem-add-code-of-testcase.patch
Patch71: 0072-etmem-add-code-of-testcase.patch
Patch72: 0073-etmem-add-testcode-script.patch
Patch73: 0074-etmem-add-code-of-testcase.patch
Patch74: 0075-etmem-testcode-adaptation.patch
Patch75: 0076-cslide-limit-hot_threshold-range-to-avoid-overflow-a.patch
Patch76: 0077-etmem-fix-the-problem-of-libso-no-permission-verific.patch
Patch77: 0078-etmem-add-config-file-permission-check.patch
Patch78: 0079-etmem-fix-problem-of-abnormal-task-value.patch
Patch79: 0080-etmem-remove-useless-dt-test-code.patch
Patch80: 0081-etmem-Fix-help-command.patch
Patch81: 0082-etmem-add-etmem-project-License-and-notice-file.patch
Patch82: 0083-etmem-fix-memory-leak.patch
Patch83: 0084-etmem-add-dt-test-code-for-permission-check.patch

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
