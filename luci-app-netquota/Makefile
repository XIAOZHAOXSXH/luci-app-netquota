include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-netquota
PKG_VERSION:=0.6.1
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-netquota
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=LuCI support for NetQuota
  DEPENDS:=+luci-base +netquota
endef

define Package/luci-app-netquota/description
  Local account authentication and shared monthly upload/download quotas.
  Capture is disabled by default; HTTP is supported and HTTPS requires a certificate.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-netquota/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./htdocs/. $(1)/www/
	$(CP) ./root/. $(1)/
	find $(1) -type d -exec chmod 0755 {} \;
	find $(1) -type f -exec chmod 0644 {} \;
endef

define Package/luci-app-netquota/postinst
#!/bin/sh
[ "$${IPKG_NO_SCRIPT}" = 1 ] && exit 0
[ -n "$${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache
rm -f /tmp/luci-modulecache/* 2>/dev/null
[ ! -x /etc/init.d/rpcd ] || /etc/init.d/rpcd restart
exit 0
endef

define Package/luci-app-netquota/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache
rm -f /tmp/luci-modulecache/* 2>/dev/null
exit 0
endef

$(eval $(call BuildPackage,luci-app-netquota))
