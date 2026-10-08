# Обновление Atlas 0.15.0

Добавлены секции по портам назначения (включая диапазоны) и TCP/UDP; точные порты и диапазоны объединяются через ИЛИ, остальные условия — через И. Старые секции поддерживаются. Формат расширен до 11 полей:

`имя | политика | домены | CIDR | источник | пул | исходящий интерфейс | DNS resolver | входящие интерфейсы | порты | tcp/udp`

Пример блокировки UDP для устройства:

`Игры | block | | | 192.168.1.25/32 | | | | | 443,10000-20000 | udp`

Секции с портами/транспортом не создают DNS/FakeIP правила, чтобы блокировка одного порта не блокировала весь домен. Для доменного FakeIP используйте отдельную секцию без портов/транспорта. DNS resolver вместе с портами/транспортом отклоняется.

Проверка серверов использует максимум два диагностических процесса при MemAvailable >= 256 МиБ, иначе один. При недоступности concurrent.futures используется последовательная проверка. Результаты сохраняются по завершении каждого узла; исключение одного узла не прекращает остальные проверки. Кеш диагностических процессов отключён.

Это дополнение к исторической матрице ниже; оно не подтверждает превосходство по производительности или совместимости.

# Atlas and Podkop capability matrix — 0.14.0

This is a capability inventory, not a claim of drop-in compatibility. It compares Atlas with the Podkop [sections](https://podkop.net/docs/sections/), [settings](https://podkop.net/docs/settings/), [FakeIP](https://podkop.net/docs/fakeip/) and [DNS](https://podkop.net/docs/dns/) feature families. Atlas uses a separate LuCI UI and sing-box runtime.

| Capability | Atlas 0.14.0 | State |
| --- | --- | --- |
| Happ `crypt5` import | Local key-backed AES-GCM decryption; strict URL/body parsing | The supplied link decrypted and saved on OpenWrt. Fresh provider fetch did not succeed; 9 profiles from a historical decrypted response were imported on OpenWrt and schema-checked. No live node/Estonian exit was verified. |
| Subscription management | 64 HTTPS sources, up to 512 nodes each and 4096 total; batch import of up to 64 URLs; 4 MiB response bound | Implemented; duplicate sources and invalid rows are reported separately. |
| Inline profile import | Paste URI/Base64/Clash YAML/sing-box JSON; up to 256 KiB; engine preflight; local sources can be toggled | Implemented; never fetches a local source from the network. |
| Subscription refresh | Provider headers, HTTPS same-origin redirects, ETag/Last-Modified, added/removed profile report | Implemented; secrets are stored on router and omitted from status; last good nodes survive failed refresh. |
| URI/formats/protocols | URI, Base64 URI, Clash/Mihomo YAML, sing-box JSON; VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS4/4a/5, HTTP | Implemented with a bounded safe YAML loader, no aliases/duplicate keys, strict URI parsing and sing-box schema validation. |
| Automatic profile selection | Manual, native fastest URLTest, or criteria selection: fastest/slowest/stable RTT, RTT bounds, preferred/excluded countries, protocol and name filters | Provider labels by default; optional HTTPS exit-country lookup and strict verified-country filters. Fresh measured country overrides the profile name; unknown or expired evidence can be excluded. |
| Section pools and policies | Independent subscription pools; `proxy`, `direct`, `exclude`, `block`, and existing VPN interface policies | Criteria are applied separately to each selector, including pools when the main selector is manual. Custom criteria start blocked and reject traffic when no fresh sample qualifies; selection is revisited by the minute scheduler. |
| Device/interface routing | Source IP/CIDR, include/exclude device rules, or selected incoming Linux interface | Incoming interface addresses are expanded to their current IPv4/IPv6 subnets at apply time. Interface must exist and have an address. |
| Domain-specific DNS | UDP/DoT/DoH per routing section, routed through that section's proxy, direct path, or VPN interface | Implemented. UDP DNS is unencrypted. |
| DNS and FakeIP | Cloudflare/AdGuard/custom DNS, IP bootstrap DoH/DoT, DNS hijack rules, FakeIP for main domains, section domains and remote domain/SRS lists, configurable TTL and cache | Implemented; self-test queries local dnsmasq for an uncached name and verifies a FakeIP A response in 198.18.0.0/15; client packet paths remain outside this test. |
| Fail-closed | Optional fw4 rule blocks LAN-to-WAN forwarding if traffic falls back outside the Atlas TUN | Installed and removed on OpenWrt 24.10.7; `fw4 print` confirmed the drop rule precedes the LAN-to-WAN allow. Router-originated traffic and LAN-local traffic are not blocked. Self-test reads the live UCI rule. |
| Ads and routing lists | AdGuard DNS, local block rules, local UTF-8 `.txt`/`.lst`/`.json` imports, 16 HTTPS lists, 24 community SRS presets, domains/hosts/CIDR/AdGuard/JSON/SRS | Implemented. Local imports are limited to 64 KiB; remote list cache keeps the last good version on failure. |
| List-update privacy | Shared or subscription-specific proxy pool, authenticated loopback fetch listener, no direct fallback when enabled | Implemented. |
| DHCP/dnsmasq DNS handoff | Optional UCI `server=127.0.0.42`, `noresolv=1`, `cachesize=0` management and restore of previous values | Implemented, off by default. It touches only these options, records the original values and restores only values still owned by Atlas. Test on the target dnsmasq configuration before enabling. |
| Runtime monitoring | Active connections, matched rules, process RSS and traffic counters | Implemented in the administrator-only LuCI tab. The sing-box API remains bound to loopback; unlike a remote YACD panel, Atlas does not expose it to WAN. |
| Storage controls | Runtime config in flash/RAM; cache in flash/RAM/external mount | Implemented. External cache requires a mounted volume under `/mnt` or `/media`; persistent subscription settings remain under `/etc/atlas`. |
| Diagnostics and privacy | Config audit; self-test for sing-box, service, loopback API, TUN, DNS, HTTPS and firewall guard; node probes; optional direct-versus-proxy public-IP comparison | Implemented. The browser button queries its own IPv4/IPv6 exits and gathers local WebRTC ICE candidates without STUN. Results stay in page memory. Optional browser FakeIP diagnostics uses explicit diagnostic DNS/routes and compares direct/proxy exits through Podkop check services. Browser logic is mocked and engine schema checked; external end-to-end result remains unverified. STUN leaks and fingerprints remain unmeasured. |
| OpenWrt lifecycle | Architecture-independent `.ipk`, procd, nft auto-redirect, preflight, rollback, bounded watchdog and optional netifd `ifup` monitor | Atlas 0.13.0 installed with `opkg`; sing-box started, `atlas0` and fw4 rules were confirmed on OpenWrt 24.10.7 x86/64 in QEMU. External HTTPS egress is denied by this execution environment. |

## Remaining differences

- There is no free-form LuCI editor for arbitrary sing-box JSON. Extra supported outbounds can be imported from a JSON subscription and schema-checked.
- Atlas does not claim browser anonymity. Its router comparison binds the baseline to the WAN interface and retains only the comparison. Browser addresses remain transient in the page.
- Custom strategies preserve FakeIP mappings. Each process launch gets a fresh selector-cache namespace, including procd respawns; groups start blocked until fresh eligible measurements. Verified on sing-box 1.12.22; later engine versions require regression checks.
- Ready APK packages for OpenWrt 25.12, ARM/MIPS installs, external validation of browser FakeIP diagnostics, unrestricted outbound editing and same-hardware Podkop resource/speed comparison remain unverified or unimplemented.
- Criteria enforce observed URLTest delays, not a continuous upper bound on future network latency. Custom selection is revisited once a minute.
- FakeIP is not generated for sections combining destination CIDR and domain matches. Source-specific DNS rules require DNS requests that retain client source addresses; dnsmasq forwarding can hide those addresses.
- Exit-country verification requires reachable proxy and ipapi.co. The strict mode excludes profiles without a recent result; the returned country comes from the external service’s geolocation database.

## Routing section syntax

New sections accept nine fields; existing eight-field lines continue to work:

`name | proxy/direct/exclude/block/interface | domains | destination CIDR | source IP/CIDR | subscription ID | outbound interface | DNS resolver | incoming interface(s)`

Comma-separated entries within a field are alternatives. Non-empty match fields within one section are combined. Sections apply top to bottom. `proxy` uses the shared automatic pool unless a subscription ID is set. `interface` binds outbound traffic to an existing VPN interface such as `wg0`. The last field maps selected LAN interface address ranges into source-IP rules.

Remote lists use six legacy fields or an optional seventh outbound-interface field:

`name | public HTTPS URL | proxy/direct/exclude/interface/block/dnsblock | auto/domains/hosts/cidrs/adguard/json/srs | on/off | ID | interface`

## Verification boundary

Version 0.13.0 additionally passed real local VLESS/HTTPS selection in two pools, max-ping rejection and recovery, and section/list FakeIP with an empty main domain list. These controlled fixtures do not prove public-provider connectivity. Version 0.13.0 was installed on OpenWrt 24.10.7 x86/64 QEMU. Bundled PyYAML 6.0.3 parsed Clash YAML; AnyTLS and YAML-generated outbounds passed `sing-box check` 1.12.22; batch and inline import RPC, service start, monitor API, actual FakeIP DNS response via dnsmasq, dnsmasq restore and empty-country-pool fail-closed passed. The provider and real proxy endpoint could not be reached, so no live provider session or Estonia exit is claimed. This is a real OpenWrt image under QEMU, not a physical router. ARM/MIPS devices and client-side leak tests remain unverified.

## 0.14 additions

FakeIP persistence now coexists with strict selector startup. Apply waits for the engine API before committing the active/last-good configuration. Browser FakeIP diagnostics is off by default and requires explicit enable/apply, then a separate check. Direct diagnostic traffic is limited to `fakeip.podkop.fyi`; `ip.podkop.fyi` uses the proxy. A native SDK builder accepts an official SDK and collects its IPK/APK output; a ready 25.12 APK has not been built or tested. No assertion of superiority in every parameter is made.
