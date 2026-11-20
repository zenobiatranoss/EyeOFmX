%global _build_id_links none

Name:           eyeofmx
Version:        @VERSION@
Release:        1%{?dist}
Summary:        Native GTK 3 monitoring and security inspector for all Linux

License:        MIT
URL:            https://github.com/zenobiatranoss/EyeOFmX
Vendor:         Zenobia
Packager:       Zenobia
BuildArch:      @RPM_ARCH@

Requires:       gtk3
Requires:       hicolor-icon-theme

%description
Created by Zenobia. For NT Protection.

EyeOFmX shows active sockets, listening ports, owning processes, critical
/etc files, live activity, shell command history, structured findings from
security tools already installed on the system and a brief comprehensive
posture report aggregating rootkit, malware, integrity and file checks.
Optional scanning engines can be installed through an explicit, authenticated
prompt using the correct packages for the detected distribution.

It works across common Linux distributions. The interface is native GTK 3
and every collector is read-only;
installing tools is a separate confirmed action.

%prep

%build

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/licenses/%{name}
install -m 0755 %{_sourcedir}/eyeofmx %{buildroot}%{_bindir}/eyeofmx
install -m 0644 %{_sourcedir}/io.github.eyeofmx.desktop \
    %{buildroot}%{_datadir}/applications/io.github.eyeofmx.desktop
install -m 0644 %{_sourcedir}/LICENSE \
    %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%files
%{_bindir}/eyeofmx
%{_datadir}/applications/io.github.eyeofmx.desktop
%{_datadir}/licenses/%{name}/LICENSE

%changelog
* Sat Nov 21 2026 Zenobia <zenobia@users.noreply.github.com> - @VERSION@-1
- Prebuilt binary package for all Linux distributions. For NT Protection.
