Name:           midori-vpn
Version:        2.0.0
Release:        1
Summary:        Secure Midori VPN client for Linux
License:        AGPL-3.0-or-later
URL:            https://github.com/goastian/midorivpn-desktop
BuildArch:      x86_64

Requires:       bash
Requires:       curl
Requires:       gawk
Requires:       e2fsprogs
Requires:       jq
Requires:       libcap-progs
Requires:       nftables
Requires:       openvpn >= 2.7
Requires:       strongswan >= 6.0
Requires:       polkit
Requires:       /usr/bin/ip
Requires:       wireguard-tools
Requires:       xdg-utils
# Qt shared-library capabilities are derived automatically from the tray
# executable. Do not hard-code distribution-specific Qt package names.
Recommends:     checkpolicy
Recommends:     policycoreutils

%description
MidoriVPN is the Linux client for secure WireGuard, authenticated encapsulated
transports, OpenVPN 2.7/DCO and strongSwan 6/IKEv2 EAP-TLS gateways. The package includes
a native Go agent and a Qt 6 system-tray integration that opens the
authenticated Vue dashboard.

%prep

%build

%install
install -d %{buildroot}/usr/bin
install -d %{buildroot}/usr/libexec
install -d %{buildroot}/usr/share/midorivpn/ui
install -d %{buildroot}/usr/share/midorivpn/selinux
install -d %{buildroot}/usr/share/doc/midori-vpn
install -d %{buildroot}/usr/share/licenses/midori-vpn
install -d %{buildroot}/usr/share/applications
install -d %{buildroot}/usr/share/icons/hicolor/32x32/apps
install -d %{buildroot}/usr/share/icons/hicolor/128x128/apps
install -d %{buildroot}/usr/share/icons/hicolor/256x256/apps
install -d %{buildroot}/usr/share/polkit-1/actions
install -d %{buildroot}/etc/polkit-1/rules.d
install -d %{buildroot}/etc/midorivpn
install -d %{buildroot}/etc/apparmor.d

install -m 0755 %{source_dir}/agent/target/release/agent %{buildroot}/usr/libexec/midorivpn-agent
install -m 0755 %{source_dir}/desktop-qt/build/midorivpn-desktop-ui %{buildroot}/usr/libexec/midorivpn-desktop-ui
install -m 0755 %{source_dir}/packaging/midorivpn-launcher %{buildroot}/usr/bin/midorivpn-desktop
install -m 0755 %{source_dir}/scripts/benchmark-transports.sh %{buildroot}/usr/bin/midorivpn-benchmark
cp -a %{source_dir}/dist/. %{buildroot}/usr/share/midorivpn/ui/
install -m 0644 %{source_dir}/config.env.example %{buildroot}/usr/share/doc/midori-vpn/config.env.example
install -m 0644 %{license_file} %{buildroot}/usr/share/licenses/midori-vpn/LICENSE
install -m 0644 %{source_dir}/packaging/launcher.env.example %{buildroot}/etc/midorivpn/launcher.env
install -m 0644 %{source_dir}/packaging/launcher/midorivpn.desktop %{buildroot}/usr/share/applications/midorivpn.desktop
install -m 0644 %{source_dir}/packaging/icons/midorivpn-32.png %{buildroot}/usr/share/icons/hicolor/32x32/apps/midorivpn.png
install -m 0644 %{source_dir}/packaging/icons/midorivpn-128.png %{buildroot}/usr/share/icons/hicolor/128x128/apps/midorivpn.png
install -m 0644 %{source_dir}/packaging/icons/midorivpn-256.png %{buildroot}/usr/share/icons/hicolor/256x256/apps/midorivpn.png
install -m 0644 %{source_dir}/packaging/polkit/org.astian.midorivpn.policy %{buildroot}/usr/share/polkit-1/actions/org.astian.midorivpn.policy
install -m 0644 %{source_dir}/packaging/polkit/49-midorivpn.rules %{buildroot}/etc/polkit-1/rules.d/49-midorivpn.rules
install -m 0644 %{source_dir}/packaging/selinux/midorivpn.te %{buildroot}/usr/share/midorivpn/selinux/midorivpn.te
install -m 0644 %{source_dir}/packaging/selinux/midorivpn.fc %{buildroot}/usr/share/midorivpn/selinux/midorivpn.fc
install -m 0644 %{source_dir}/packaging/apparmor/usr.libexec.midorivpn-agent %{buildroot}/etc/apparmor.d/usr.libexec.midorivpn-agent

%post -p /usr/bin/bash -f %{source_dir}/packaging/maintainer/postinst
%preun -p /usr/bin/bash -f %{source_dir}/packaging/maintainer/prerm
%posttrans -p /usr/bin/bash -f %{source_dir}/packaging/maintainer/posttrans

%files
%license /usr/share/licenses/midori-vpn/LICENSE
%config(noreplace) %attr(0644,root,root) /etc/midorivpn/launcher.env
%config /etc/apparmor.d/usr.libexec.midorivpn-agent
/etc/polkit-1/rules.d/49-midorivpn.rules
/usr/bin/midorivpn-desktop
/usr/bin/midorivpn-benchmark
/usr/libexec/midorivpn-agent
/usr/libexec/midorivpn-desktop-ui
/usr/share/applications/midorivpn.desktop
/usr/share/doc/midori-vpn/config.env.example
/usr/share/icons/hicolor/32x32/apps/midorivpn.png
/usr/share/icons/hicolor/128x128/apps/midorivpn.png
/usr/share/icons/hicolor/256x256/apps/midorivpn.png
/usr/share/midorivpn/ui
/usr/share/midorivpn/selinux
/usr/share/polkit-1/actions/org.astian.midorivpn.policy

%changelog
* Mon Aug 31 2026 Astian, Inc. <support@astian.org> - 2.0.0-1
- Bind disconnect requests to the active tunnel and preserve it across settings refreshes.

* Thu Aug 27 2026 Astian, Inc. <support@astian.org> - 2.0.0-1
- Enforce one tray instance and use the packaged MidoriVPN icon.
- Keep permission restarts in the current browser tab and require complete DNS capabilities.
- Restore resolver state after unclean exits and simplify localized settings.

* Sun Aug 23 2026 Astian, Inc. <support@astian.org> - 2.0.0-1
- Replace the Linux GTK3 shell with the native agent and authenticated loopback UI.
- Add device-owned certificate enrollment and a DCO-required OpenVPN 2.7 client.
- Add a private strongSwan 6 client with EAP-TLS and an XFRM interface.
