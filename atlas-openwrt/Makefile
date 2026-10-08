include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-atlas
PKG_VERSION:=0.28.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-atlas
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Atlas - subscriptions and routing for sing-box
  DEPENDS:=+luci-base +rpcd +python3-light +python3-logging +python3-urllib +python3-openssl +python3-uuid +python3-codecs +python3-cryptography +ca-bundle +sing-box +kmod-tun +kmod-nft-tproxy +kmod-nft-socket +kmod-nft-queue +firewall4 +ip-full
endef

define Package/luci-app-atlas/description
  Subscription manager with LuCI dashboard, strict import, URL tests,
  selective routing and validated sing-box configuration deployment.
  Requires sing-box 1.12 or newer. Experimental, test on your router first.
endef

define Build/Compile
endef

define Package/luci-app-atlas/conffiles
/etc/atlas/state.json
endef

define Package/luci-app-atlas/install
	$(CP) ./root/* $(1)/
	find $(1) -type f -name '*.pyc' -delete
	find $(1) -type d -name __pycache__ -empty -delete
	$(INSTALL_DIR) $(1)/etc/atlas
	chmod 700 $(1)/etc/atlas
	chmod 600 $(1)/etc/atlas/state.json
	chmod 755 $(1)/etc/init.d/atlas $(1)/etc/uci-defaults/90-atlas $(1)/etc/hotplug.d/iface/95-atlas $(1)/usr/libexec/rpcd/atlas
endef

define Package/luci-app-atlas/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
[ ! -f /etc/uci-defaults/90-atlas ] || { /etc/uci-defaults/90-atlas && rm -f /etc/uci-defaults/90-atlas; }
/etc/init.d/rpcd restart
/etc/init.d/rpcd start
exit 0
endef

define Package/luci-app-atlas/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
[ "$${PKG_UPGRADE:-0}" = 1 ] && exit 0
[ "$${1:-}" = upgrade ] && exit 0
/etc/init.d/atlas stop
/etc/init.d/atlas disable
sed -i '/atlas[.]py scheduled/d' /etc/crontabs/root
exit 0
endef

$(eval $(call BuildPackage,luci-app-atlas))
