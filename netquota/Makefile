include $(TOPDIR)/rules.mk

PKG_NAME:=netquota
PKG_VERSION:=0.6.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/netquota
  SECTION:=net
  CATEGORY:=Network
  TITLE:=NetQuota account and shared quota management
  DEPENDS:=+lua +lua-cjson +openssl-util +lsqlite3 +luci-lib-nixio +luci-lib-jsonc +libuci-lua +libubus-lua +libubox-lua +kmod-nft-core +nftables-nojson
endef

define Package/netquota/description
  Local account authentication and shared monthly upload/download quotas.
  Capture is disabled by default; HTTP is supported and HTTPS requires a certificate.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/netquota/conffiles
/etc/config/netquota
endef

define Package/netquota/install
	$(INSTALL_DIR) $(1)
	$(CP) ./files/. $(1)/
	find $(1) -type d -exec chmod 0755 {} \;
	find $(1) -type f -exec chmod 0644 {} \;
	chmod 0755 $(1)/etc/firewall.netquota
	find $(1)/usr/sbin $(1)/usr/libexec $(1)/etc/init.d $(1)/etc/hotplug.d -type f -exec chmod 0755 {} \;
	find $(1)/usr/share/netquota/portal/cgi-bin $(1)/usr/share/netquota/redirect/cgi-bin -type f -exec chmod 0755 {} \;
endef

define Package/netquota/postinst
#!/bin/sh
[ "$${IPKG_NO_SCRIPT}" = 1 ] && exit 0
[ -n "$${IPKG_INSTROOT}" ] && exit 0
# Existing releases were HTTPS-only. Preserve their transport on upgrade;
# fresh installations contain an explicit portal_mode=http in the conffile.
if [ -f /etc/config/netquota ] && [ -z "$$(uci -q get netquota.main.portal_mode)" ]; then
 uci set netquota.main.portal_mode=https && uci commit netquota || exit 1
fi
# Register only the package-owned fw3 include; preserve capture and networking.
if [ -f /etc/firewall.netquota ]; then
 section="$$(uci -q get firewall.netquota)"
 path="$$(uci -q get firewall.netquota.path)"
 if [ -n "$$section" ] && { [ "$$section" != include ] || [ "$$path" != /etc/firewall.netquota ]; }; then
  echo 'netquota: foreign firewall.netquota section exists; refusing overwrite' >&2
  exit 1
 fi
 uci set firewall.netquota=include || exit 1
 uci set firewall.netquota.type=script || exit 1
 uci set firewall.netquota.path=/etc/firewall.netquota || exit 1
 uci set firewall.netquota.reload=1 || exit 1
 uci commit firewall || exit 1
fi
# Boot service registers the early guard. Source configuration defaults disabled.
[ ! -x /etc/init.d/netquota ] || /etc/init.d/netquota enable || exit 1
echo 'netquota installed; existing capture setting preserved; service not started.'
exit 0
endef

define Package/netquota/postrm
#!/bin/sh
[ "$${IPKG_NO_SCRIPT}" = 1 ] && exit 0
[ -n "$${IPKG_INSTROOT}" ] && exit 0
case "$$1" in upgrade|failed-upgrade) exit 0 ;; esac
[ "$${PKG_UPGRADE:-0}" = 1 ] && exit 0
if [ ! -f /etc/config/netquota ] && [ -f /etc/netquota/config.removed ]; then
 umask 077
 cp /etc/netquota/config.removed /etc/config/netquota || exit 1
fi
exit 0
endef

define Package/netquota/prerm
#!/bin/sh
[ "$${IPKG_NO_SCRIPT}" = 1 ] && exit 0
[ -n "$${IPKG_INSTROOT}" ] && exit 0

# Stopping the service must never abort a package operation. The daemon is
# respawn-managed, and `ubus call service delete` legitimately reports
# "Not found" when procd is not currently tracking the instance; leaving a package
# half-removed is worse than a briefly surviving process.
stop_service() {
	# A failed/no-op procd stop is harmless only after the active network is guarded.
	if [ "$$(uci -q get netquota.main.enabled)" = 1 ]; then
		/usr/sbin/netquota --guard || return 1
	fi
	[ -x /etc/init.d/netquota ] || return 0
	/etc/init.d/netquota stop >/dev/null 2>&1
	return 0
}

case "$$1" in
	upgrade|failed-upgrade)
		stop_service || exit 1
		exit 0
		;;
esac

if [ "$${PKG_UPGRADE:-0}" = 1 ]; then
	stop_service || exit 1
	exit 0
fi

# Refuse to remove while capture is active: pulling the rules out from under live
# traffic would silently re-open the network. Both canonical and legacy keys matter.
for key in netquota.main.enabled netquota.settings.enabled; do
	value="$$(uci -q get "$$key")"
	case "$$value" in
		1|true|yes|on|enabled)
			echo 'netquota: disable capture explicitly before removal:' >&2
			echo 'uci set netquota.main.enabled=0; uci commit netquota; /etc/init.d/netquota restart' >&2
			exit 1
			;;
	esac
done

stop_service

if [ "$$(uci -q get dhcp.netquota_portal.netquota_owned)" = 1 ]; then
	uci delete dhcp.netquota_portal && uci commit dhcp || exit 1
	/etc/init.d/dnsmasq reload || exit 1
fi

# The CLI performs idempotent cleanup only when capture is disabled. A non-zero exit
# means the nftables/iptables teardown genuinely failed, which is worth stopping for.
if [ -x /usr/sbin/netquota ]; then
	if ! /usr/sbin/netquota --cleanup >/dev/null 2>&1; then
		echo 'netquota: rule cleanup failed; refusing to remove the package' >&2
		exit 1
	fi
fi

if [ "$$(uci -q get firewall.netquota)" = include ] && \
   [ "$$(uci -q get firewall.netquota.path)" = /etc/firewall.netquota ]; then
	uci delete firewall.netquota && uci commit firewall || exit 1
fi

# opkg may delete an unchanged conffile; postrm restores this owned backup.
if [ -f /etc/config/netquota ]; then
	umask 077
	mkdir -p /etc/netquota || exit 1
	cp /etc/config/netquota /etc/netquota/config.removed || exit 1
	chmod 600 /etc/netquota/config.removed
fi

exit 0
endef

$(eval $(call BuildPackage,netquota))
