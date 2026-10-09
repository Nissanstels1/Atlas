# Atlas для OpenWrt

Установка приложения, LuCI и Atlas Engine одной командой в терминале роутера под root:

```sh
wget -O /tmp/atlas-install.sh https://raw.githubusercontent.com/Nissanstels1/Atlas/main/install.sh && sh /tmp/atlas-install.sh
```

Поддерживаются OpenWrt 24.10.1+ со стабильным номером версии, ARM64/aarch64_generic (включая NanoPi R4SE) и x86_64. Выбираются IPK/opkg или APK/apk, проверяются SHA256, устанавливаются LuCI и зависимости из feeds прошивки. APK не подписаны публичным ключом; bootstrap явно использует allow-untrusted после проверки SHA256. Физический NanoPi ещё не испытан. Для других архитектур автоматический полный комплект пока не готов.

После установки: **LuCI → Службы → Atlas**. Добавьте подписку, обновите и проверьте серверы, примените настройки. Конфликтующие службы автоматически не удаляются; маршрутизация не включается без настройки.

Установщик из `main/install.sh` дополнительно устанавливает зависимости Python, проверяет запуск серверной части и наличие объекта `atlas` в RPC. Ошибка любой из этих проверок завершает установку с ненулевым кодом. Пакеты выпуска 0.28.3 остаются прежними.

Если в LuCI появляется `atlas/status: Object not found`, выполните `/usr/libexec/rpcd/atlas list` в SSH. Сообщение `/usr/bin/python3: not found` означает, что Python не установлен. Восстановление зависимостей через feeds вашей прошивки:

```sh
(
set -e
if command -v opkg >/dev/null 2>&1; then
    opkg update
    opkg install python3 python3-cryptography
elif command -v apk >/dev/null 2>&1; then
    apk update
    apk add python3 python3-cryptography
else
    echo 'No supported package manager.'
    exit 1
fi
/usr/libexec/rpcd/atlas list
/etc/init.d/rpcd restart
sleep 2
ubus list atlas
)
```

Если последняя команда вывела `atlas`, обновите страницу через Ctrl+F5. Если установка пакетов завершилась ошибкой, сохраните её полный вывод: наличие пункта меню не подтверждает успешную установку зависимостей.

[Atlas 0.28.3 — пакеты и исходники](https://github.com/Nissanstels1/Atlas/releases/tag/v0.28.3-beta). Установщик привязан к этому выпуску. Повторная команда устанавливает этот же выпуск, а не произвольную будущую версию.

[Исходники приложения](atlas-openwrt) · [проверки и ограничения](atlas-openwrt/docs/release-0.28.3.md).

358 Linux-тестов без ошибок и пропусков с настоящими движками. Сборки движка x86_64 и ARM64; исходники GPL-3.0-or-later, лицензии и зависимости включены в выпуск. Нет подтверждённого превосходства по скорости/RAM над Podkop, общей квоты FakeIP или длительных испытаний на физическом роутере.
