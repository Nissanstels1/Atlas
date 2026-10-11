'use strict';
'require view';
'require rpc';
'require poll';
'require ui';

var api = {
    status: rpc.declare({ object: 'atlas', method: 'status', expect: {} }),
    saveSubscription: rpc.declare({ object: 'atlas', method: 'save_subscription', params: ['id', 'name', 'url', 'enabled', 'headers', 'clear_headers'], expect: {} }),
    importProfiles: rpc.declare({ object: 'atlas', method: 'import_profiles', params: ['name', 'content', 'id'], expect: {} }),
    importSubscriptions: rpc.declare({ object: 'atlas', method: 'import_subscriptions', params: ['items'], expect: {} }),
    exportBackup: rpc.declare({ object: 'atlas', method: 'export_backup', expect: {} }),
    restoreBackup: rpc.declare({ object: 'atlas', method: 'restore_backup', params: ['content'], expect: {} }),
    diagnosticReport: rpc.declare({ object: 'atlas', method: 'diagnostic_report', expect: {} }),
    getProfiles: rpc.declare({ object: 'atlas', method: 'get_profiles', params: ['id'], expect: {} }),
    sectionDetails: rpc.declare({ object: 'atlas', method: 'section_details', params: ['id'], expect: {} }),
    deleteSubscription: rpc.declare({ object: 'atlas', method: 'delete_subscription', params: ['id'], expect: {} }),
    saveSettings: rpc.declare({ object: 'atlas', method: 'save_settings', params: ['settings'], expect: {} }),
    importRules: rpc.declare({ object: 'atlas', method: 'import_rules', params: ['content', 'target'], expect: {} }),
    action: rpc.declare({ object: 'atlas', method: 'action', params: ['operation', 'id'], expect: {} }),
    dashboardAccess: rpc.declare({object:'atlas',method:'dashboard_access',expect:{}}),
    sectionDashboard: rpc.declare({ object: 'atlas', method: 'section_dashboard', expect: {} }),
    sectionSelect: rpc.declare({ object: 'atlas', method: 'section_select', params: ['id','group','member'], expect: {} }),
    monitor: rpc.declare({ object: 'atlas', method: 'monitor', expect: {} }),
    configPreview: rpc.declare({object:'atlas',method:'config_preview',params:['validate'],expect:{}}),
    routeExplain: rpc.declare({object:'atlas',method:'route_explain',params:['query'],expect:{}}),
    sectionClone: rpc.declare({object:'atlas',method:'section_clone',params:['id','name'],expect:{}}),
    setAutostart: rpc.declare({object:'atlas',method:'set_autostart',params:['enabled'],expect:{}}),
    serviceLogs: rpc.declare({object:'atlas',method:'service_logs',expect:{}}),
    securityCompare: rpc.declare({object:'atlas',method:'security_compare',params:['observations'],expect:{}}),
    nftDiagnostics: rpc.declare({object:'atlas',method:'nft_diagnostics',expect:{}})
};

function atlasElement(tag, attrs, children) {
    var attributes = Object.assign({}, attrs || {});
    // LuCI serializes false as an attribute value; HTML boolean attributes
    // remain enabled whenever present, even when their value is "false".
    ['disabled', 'checked', 'selected', 'readonly', 'multiple', 'required', 'autofocus', 'hidden'].forEach(function(key) {
        if (attributes[key] === false) delete attributes[key];
    });
    // LuCI E() accepts a flat child list. Nested arrays otherwise become
    // literal "[object HTMLDivElement]" text and their controls disappear.
    var flattened=[];
    function append(child){if(Array.isArray(child))child.forEach(append);else if(child!=null)flattened.push(child);}
    append(children);
    return E(tag, attributes, flattened);
}
function node(tag, cls, children, attrs) {
    var element=atlasElement(tag, Object.assign({ 'class': cls || '' }, attrs || {}), children);
    if(tag==='label' && cls==='at-checkbox') {
        var title=element.textContent,help=atlasHelpBox(title);
        var control=Array.from(element.children || []).find(function(x){return (x.tagName || x.tag || '').toLowerCase()==='input';});
        if(control)control.addEventListener('change',function(){help.open=true;});
        // Keep interactive disclosures outside labels: opening help must not
        // accidentally toggle the checkbox, and help needs its own full row.
        return atlasElement('div',{'class':'at-checkbox-field'},[element,help]);
    }
    return element;
}
function label(t) { return document.createTextNode(String(t)); }
function pill(t, cls) { return node('span', 'at-pill ' + (cls || ''), label(t)); }
function date(t) { return t ? new Date(t * 1000).toLocaleString('ru-RU') : 'Ещё не обновлялась'; }
function bytes(n) {
    n = Number(n || 0);
    return n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' ГиБ' : (n / 1048576).toFixed(1) + ' МиБ';
}
function result(promise) {
    return promise.then(function(r) { if (!r || !r.ok) throw new Error(r && r.error || 'Нет ответа от Atlas'); return r; });
}
function error(e) { ui.addNotification(null, node('p', '', label(e.message || String(e))), 'error'); }
function lines(value) { return value.split(/[\n,]+/).map(function(s) { return s.trim(); }).filter(Boolean); }

function atlasDisclosures(root) {
    var occurrences={};
    return Array.from(root.querySelectorAll('details')).map(function(element){
        var summary=Array.from(element.children || []).find(function(child){return (child.tagName || child.tag || '').toLowerCase()==='summary';});
        var name=summary ? (summary.getAttribute ? summary.getAttribute('aria-label') : (summary.attributes || {})['aria-label']) || summary.textContent : '';
        var occurrence=occurrences[name] || 0;occurrences[name]=occurrence+1;
        return {key:name+'#'+occurrence,element:element};
    });
}

function atlasHelp(title,hint) {
    var entries=[
        [/^Путь DoH$/i,'Путь HTTPS-запроса к выбранному DNS-серверу. Если оставить /dns-query, Atlas будет использовать стандартный адрес DoH. Другой путь нужен только по инструкции вашего DNS-провайдера; ошибочный путь нарушит разрешение имён.','Адрес dns.example и путь /dns-query дают https://dns.example/dns-query.'],
        [/^Использовать FakeIP/i,'Выдаёт проксируемым доменам временные IP, чтобы движок сохранял имя сайта при выборе секции. Выключение возвращает реальные DNS-адреса; отдельные приложения могут требовать этого для совместимости.','Для доменных секций оставьте включённым; внешний IP этот переключатель не меняет.'],
        [/UDP over TCP/i,'Передаёт UDP внутри TCP-соединения для поддерживающих это SOCKS и Shadowsocks серверов. Если выключено, остаётся обычный UDP. Неподдерживаемая сервером версия нарушит UDP-соединения.','Включайте только если провайдер подтвердил поддержку и указал версию.'],
        [/^Задержка после подъёма WAN/i,'Сколько миллисекунд ждать после восстановления сети перед перезапуском движка, если мониторинг включён. Это даёт сети время получить адрес и маршрут. При выключенном мониторинге значение не используется.','1000 означает одну секунду; оставьте текущее значение при стабильном восстановлении.'],
        [/^Активный пул профилей$/i,'Ограничивает число профилей, передаваемых работающему движку, и расход памяти. Остальные профили остаются сохранёнными. Без лимита большие подписки могут существенно увеличить расход RAM.','512 — предел активного пула, а не предел сохранённых профилей.'],
        [/^Каталог community lists$/i,'Выберите готовый список сайтов сообщества, затем нажмите кнопку добавления и назначьте маршрут. Сам выбор в этом поле не меняет правила.','YouTube → добавить список → назначить секцию для видео.'],
        [/^Секция для обновления$/i,'Выбирает маршрут загрузки внешних списков через профили этой секции. Используется при включённой загрузке через Atlas и имеет приоритет над выбранной подпиской. При пустом значении используется подписка или общий пул.','Выберите рабочую прокси-секцию, если источник списка недоступен напрямую.'],
        [/^Один список на строку/i,'Расширенный текстовый редактор источников: каждая строка содержит поля, разделённые вертикальной чертой, в указанном порядке. Пустое поле сохраняет значение по умолчанию. Для обычной настройки удобнее добавлять списки в редакторе секции.','Видео | https://example.org/domains.txt | proxy | domains | on'],
        [/Адрес списка или file:/i,'Укажите URL файла со списком либо file:/// и абсолютный путь существующего файла на роутере. После сохранения и обновления записи этого файла направляются через секцию. Пустая строка не сохраняется; удалите её кнопкой удаления.','Домены: https://example.org/domains.txt. Локальный файл: file:///etc/atlas/domains.txt.'],
        [/Готовый список сайтов/i,'Добавляет общественный список в текущую секцию. Выбор в меню сам по себе ничего не меняет: нажмите кнопку добавления, затем сохраните и примените правила.','Для секции YouTube добавьте YouTube; для мессенджера — Telegram.'],
        [/Формат файла/i,'domains — домены, cidrs — IP и подсети, srs — бинарный список sing-box, json — правила sing-box. auto определяет текстовый формат. Существующее значение оставьте, если источник не изменился.','Для domains.txt используйте domains; для cidr_ipv4.txt — cidrs.'],
        [/Использовать список/i,'Включённый список добавляет свои записи в секцию после обновления и применения. Выключенный остаётся сохранённым, но его правила не используются.','Выключите отметку для временного отключения списка без удаления URL.'],
        [/^Включить YACD|Адрес панели/i,'Включает панель соединений sing-box. Если оставить выключенной, дополнительная панель недоступна, а маршрутизация Atlas продолжает работать. Доступ к API и сведениям о соединениях должен оставаться в доверенной локальной сети.','Для обычной настройки используйте Atlas; YACD нужен для подробного просмотра соединений.'],
        [/Разрешить адрес WAN|все интерфейсы/i,'Включение разрешает слушателю принимать соединения не только с доверенного LAN или loopback. Это может открыть прокси или API другим сетям. Если оставить выключенным, ограничения адреса сохраняются. Само разрешение не заменяет firewall и пароль.','Оставьте выключенным для домашнего роутера; не публикуйте прокси или панель в интернете.'],
        [/Отдельный HTTP|Включить listener/i,'Включение создаёт отдельный HTTP/SOCKS-прокси на заданном IP и порту. Приложение использует его только после явной настройки этого адреса в приложении; обычная маршрутизация устройств не переключается сама. Если оставить выключенным, дополнительный порт не открывается.','Для браузера с отдельным маршрутом задайте LAN IP роутера, свободный порт и пароль; проверьте firewall.'],
        [/LAN или loopback IP|Частный LAN IP|Сетевой интерфейс|VPN интерфейс|Исходящий VPN|Логические интерфейсы|Входные интерфейсы/i,'Задаёт адрес или интерфейс, к которому относится указанное правило/слушатель. Интерфейс должен уже существовать в OpenWrt: Atlas не создаёт VPN по имени. Если оставить текущий адрес или интерфейс, область действия не изменится; ошибочный адрес может сделать маршрут или порт недоступным.','br-lan — домашняя сеть, 127.0.0.1 — только роутер, wg0 — заранее настроенный WireGuard. Не указывайте WAN для доступа к локальной панели.'],
        [/TLS SNI|TLS имя/i,'Имя должно совпадать с сертификатом DNS или прокси-сервера. Если оставить правильное имя, TLS-проверка продолжит защищать соединение. Неправильное имя приводит к отказу сертификата; отключать проверку ради подключения не нужно.','Для Cloudflare DoH используйте cloudflare-dns.com; для своего сервера возьмите имя из инструкции провайдера.'],
        [/Доступ к частным адресам/i,'Включение разрешает этому источнику списка обращаться к локальным/частным адресам. Полученные данные могут влиять на правила роутера. Если оставить выключенным, такие сетевые источники отвергаются.','Включайте только для своего доверенного сервера списков внутри LAN; для обычного публичного списка оставьте выключенным.'],
        [/символьные ссылки/i,'Разрешает локальному источнику читать файл через символьную ссылку. Если оставить выключенным, такие ссылки отвергаются, что защищает от неожиданного чтения другого файла.','Для обычного списка выберите сам файл. Разрешайте ссылку только если контролируете её конечный путь.'],
        [/Перезапускать sing-box/i,'Включение перезапускает движок после восстановления выбранного подключения OpenWrt. Это может восстановить зависший маршрут, но прерывает текущие соединения. Если оставить выключенным, автоматический перезапуск по этому событию не выполняется.','Оставьте выключенным при стабильной работе; включайте, если после восстановления WAN помогает только ручной перезапуск.'],
        [/Распознанный протокол|^Протоколы|^Версия$/i,'Определяет совместимость транспорта или версию указанного протокола. Профили неподходящего типа могут исключаться из выбора; сервер должен поддерживать выбранную версию. Если оставить текущий выбор или наследование, используется сохранённая/общая настройка.','Не меняйте версию UDP-over-TCP без поддержки на сервере; фильтр типов оставьте пустым, чтобы не отбрасывать совместимые профили.'],
        [/Профили или конфигурация/i,'Импортирует профили из ссылок, Base64, Clash YAML или sing-box JSON. Настройки берутся из введённого содержимого; существующие группы не заменяются этим импортом автоматически. Если ничего не импортировать, список профилей сохранится.','Вставьте выданную провайдером vless:// ссылку или локальный JSON; не вставляйте произвольные инструкции из сайтов.'],
        [/Исключить по названию/i,'Отбрасывает профили, имя которых совпадает с фильтром. Имя задаёт провайдер и может быть неточным. Если оставить поле пустым, исключения по названию не будет.','Чтобы не выбирать профили с пометкой Test, добавьте Test; перед применением проверьте, что остаётся рабочий профиль.'],
        [/Проверять каждые/i,'Период обновления проверок доступности в секундах. Меньший интервал чаще проверяет профили и создаёт больше сетевых запросов; планировщик Atlas может выполнять проверки ограниченными порциями. Если оставить значение, частота не изменится.','Начните с 60 секунд; слишком частые проверки не гарантируют более быстрый интернет.'],
        [/Проверка скачивания/i,'При включении кандидат должен передать 64 КиБ по HTTPS перед переключением. Это отсекает серверы, которые отвечают на короткий запрос, но не передают данные. Если оставить выключенной, этого дополнительного критерия нет. Нужен совместимый Atlas Engine.','Включите для нестабильных профилей и укажите небольшой доступный HTTPS-файл; учитывайте трафик проверок.'],
        [/Готовый набор сайтов/i,'Добавляет предложенные домены или назначенный список для выбранной группы. Если оставить «Свои сайты», используйте введённые вами домены. Готовый набор не гарантирует актуальности всех зеркал или адресов сайта.','Выберите YouTube для старта; для HDRezka дополнительно укажите рабочее зеркало в проверке сайта.'],
        [/Разрешение реального IP/i,'Повторно узнаёт реальный IP домена перед проверкой правил, которым нужен этот адрес. Если оставить выключенным, лишнего запроса не будет; правила по IP при FakeIP могут требовать дополнительного разрешения. Включение добавляет DNS-запросы и задержку.','Для обычной группы доменов оставьте выключенным; включайте при сочетании FakeIP и правил по реальным IP.'],
        [/Секция на строку/i,'Экспертный формат для ввода нескольких групп. Каждая строка описывает отдельную группу; ошибки формата не дают сохранить изменения. Если оставить текст без изменений, группы сохранят прежние условия.','Для обычной настройки используйте карточки групп или мастер; текстовый ввод нужен для массового редактирования.'],
        [/HaGeZi|Peter Lowe/i,'Включённая отметка добавляет этот DNS-список в фильтрацию после применения. Выключенная сохраняет источник, но отключает его правила. Если оставить текущие отметки, выбранные списки не изменятся.','Обычно выберите один готовый фильтр основной кнопкой; сочетайте списки только если понимаете, какие домены они блокируют.'],
        [/Режим маршрутизации|Остальные сайты|Весь внешний трафик/i,'«По группам» отправляет через прокси только выбранные сайты; остальные идут напрямую. «Глобальный» отправляет остальной трафик через общий прокси, но сохраняет прямые исключения. Если оставить текущий режим, основной маршрут не изменится.','Для YouTube через прокси, а банков напрямую выберите группы. Для основного трафика через прокси выберите глобальный режим и проверьте исключения.'],
        [/DoH|обходные DNS/i,'Включение блокирует известные публичные серверы защищённого DNS, чтобы браузеры реже обходили DNS-фильтр Atlas. Если оставить выключенным, браузер с собственным DoH может обходить блокировку рекламы. Принудительный DoH при блокировке может перестать работать; неизвестные DoH адреса не обнаруживаются.','Оставьте выключенным для первого запуска; если реклама обходит фильтр, проверьте защищённый DNS браузера и включите блокировку известных серверов.'],
        [/QUIC/i,'Включение блокирует UDP/443: приложения, поддерживающие запасной транспорт, переходят на TCP. Если оставить выключенным, QUIC продолжит работать. Это может улучшить совместимость некоторых прокси, но ухудшить скорость или доступность приложений без TCP.','Включайте при проблемах YouTube через UDP; если всё работает, оставьте выключенным.'],
        [/NTP/i,'Включение отправляет синхронизацию времени напрямую. Если оставить выключенным, NTP следует обычным маршрутам. Прямой NTP раскрывает серверу времени внешний IP роутера.','Оставьте включённым, если через прокси часы роутера не синхронизируются; для строгого прокси-маршрута проверьте доступность NTP и выключите исключение.'],
        [/Разрывать текущие/i,'Включение закрывает соединения при смене профиля: новые запросы идут через выбранный сервер. Если оставить выключенным, существующие сеансы могут продолжить работу через старый сервер до завершения. Включение может прервать видео, скачивание и звонок.','Оставьте выключенным для плавной смены; включайте только если нужно немедленно прекратить использование старого профиля.'],
        [/HTTP-заголовки|Удалить сохранённые заголовки/i,'Некоторые провайдеры требуют заголовки при скачивании подписки. Пустое поле сохраняет уже сохранённые заголовки; отметка удаления их стирает. Без требуемого провайдером заголовка обновление может отказать.','Обычно оставьте пустым. Вносите Authorization или User-Agent только по инструкции вашего провайдера.'],
        [/Использовать подписку/i,'Включённая подписка предоставляет профили для выбора и обновляется по расписанию. Выключенная сохраняется, но её профили не участвуют в активном выборе. Если оставить текущую отметку, доступность этой подписки не изменится.','Выключите старую подписку, сохранив её для возврата; перед применением убедитесь, что в группе остаётся рабочее подключение.'],
        [/Группа включена|Секция включена/i,'Включённая группа участвует в проверке правил. Выключенная группа сохраняет сайты и настройки, но трафик переходит к следующим группам или основному маршруту. Если оставить включённой, её правила продолжат действовать.','Выключите группу для временной проверки, затем убедитесь, какой маршрут получит её трафик без этого правила.'],
        [/Загружать.*списки.*прокси/i,'Включение загружает списки через выбранный прокси Atlas, без прямого запасного выхода. Если оставить выключенным, загрузка идёт напрямую. При недоступном прокси обновление не завершится, а прежние рабочие списки сохранятся.','Включите для недоступных напрямую источников; сначала проверьте подключение и примените настройки канала обновления.'],
        [/Направлять DNS|DNS dnsmasq|DNS устройств/i,'Включение направляет запросы dnsmasq через DNS Atlas: устройства с DNS роутера получают доменные правила и фильтр. Если оставить выключенным, DNS dnsmasq не перенаправляется этим механизмом; FakeIP и фильтрация могут не работать на этих устройствах. Собственный DoH клиента проверяется отдельно.','Для обычной домашней сети используйте DNS роутера и включите интеграцию; после применения проверьте открытие обычного сайта.'],
        [/Уровень журнала/i,'Определяет подробность сообщений. Error показывает ошибки, Info добавляет события, Debug собирает много деталей и может раскрывать посещаемые адреса. Если оставить текущий уровень, объём и подробность журналов не изменятся.','Для обычной работы используйте warn или error; debug включайте только на время диагностики.'],
        [/Рабочая конфигурация|Кеш DNS\/FakeIP|Путь кеша|Внешний каталог/i,'RAM уменьшает записи на накопитель, но данные могут пропасть при перезагрузке. Постоянное хранилище сохраняет конфигурацию или кеш между загрузками и использует диск. Если оставить текущий вариант, место хранения не изменится. Не удаляйте активный кеш FakeIP: клиенты могут ещё использовать выданные адреса.','Для NanoPi можно хранить конфигурацию постоянно, а кеш в RAM; внешний каталог выбирайте только на доступном после загрузки диске.'],
        [/Обновлять подписки/i,'Задаёт интервал скачивания новых профилей и списков, в часах. Если оставить текущий интервал, расписание не изменится. Слишком частое обновление создаёт лишние запросы к провайдеру; оно не ускоряет переключение серверов.','12 часов подходит для редких изменений подписки; проверка серверов настраивается отдельно в секундах.'],
        [/Максимальный размер файла/i,'Ограничивает размер скачиваемого списка. Если оставить 4 МиБ, более крупный источник будет отклонён с сохранением предыдущей версии. 0 снимает этот предел и может увеличить потребление памяти.','Для HaGeZi Light достаточно стандартного предела; увеличивайте только для конкретного большого списка.'],
        [/Маршрут группы|^Действие|Действие для правил|Маршрут каталога|Выход списка/i,'Прокси направляет совпавший трафик через выбранные профили; напрямую использует интернет провайдера; блокировать запрещает соединение; VPN-интерфейс использует указанный готовый интерфейс. Исключение внутри группы передаёт проверку следующей группе. Если оставить маршрут, поведение совпавшего трафика не изменится.','YouTube → прокси; банк → напрямую; трекеры → блокировать.'],
        [/Выбор профиля|Профиль для ручного|Активный пул/i,'Автоматический выбор использует доступные профили и критерии этой группы. Ручной выбор закрепляет конкретный профиль; при его отказе нельзя рассчитывать на автоматическую замену этого выбора. Если оставить авто, Atlas продолжит подбор.','Начните с авто; закрепляйте профиль только после проверки нужного сайта через него.'],
        [/Fail.closed|аварийн|защит.*обрыв|Kill.switch/i,'Защита при отказе запрещает защищаемый трафик, если туннель недоступен. Это может отключить доступ к интернету для выбранных устройств; сначала проверьте рабочий маршрут.','Включайте после проверки профилей и храните способ доступа к роутеру по локальной сети.'],
        [/поряд.*групп|групп.*поряд/i,'Сайты и назначенные списки проверяются вместе, сверху вниз по группам. Первое совпадение определяет маршрут. Глобальные исключения и глобальные блокировки сохраняют приоритет.','Разместите группу с узким правилом выше общей группы с большим списком.'],
        [/STUN/i,'STUN помогает браузеру узнать публичный адрес WebRTC. Запрос отправляется внешнему серверу только после вашего выбора; камера и микрофон не требуются.','Сравните адрес с измеренным выходом провайдера; недоступный STUN означает непроверенный результат.'],
        [/Пул|Подключение|подписк/i,'Подключение содержит профили доступа к прокси. Группа может использовать свой набор профилей независимо от других групп.','Группа YouTube → подписка «Видео»; группа Работа → другая подписка.'],
        [/Адрес сайта|URL проверки|HTTPS URL|сайт для проверки/i,'Это адрес, который Atlas запрашивает через каждый кандидат. Указывайте конечную HTTPS страницу: перенаправление или HTTP ошибка не считаются успешной проверкой сайта.','https://www.youtube.com/ и ожидаемый ответ 200. Успех страницы не гарантирует работу видеопотока.'],
        [/HTTP ответы/i,'Профиль допускается только после одного из указанных успешных кодов HTTP. Коды отказа не разрешены.','200 — обычная страница; 204 — пустой диагностический ответ.'],
        [/Текст.*страниц/i,'Atlas ищет этот текст в первых 64 КиБ ответа. Это помогает исключить заглушки, но сайт может менять содержимое или возвращать CAPTCHA.','Для собственной тестовой страницы используйте постоянную строку atlas-ok.'],
        [/Исключ.*домен|Домены-исключения/i,'Глобальное исключение направляет эти домены напрямую раньше групп. Исключение внутри группы передаёт запрос следующим группам.','Внутренняя корпоративная сеть может идти напрямую, остальные сайты — через прокси.'],
        [/Домен|Сайты/i,'Укажите имя сайта без https://, порта и пути. Правило домена включает его поддомены. Несколько доменов одной группы используют одинаковый маршрут.','youtube.com включает www.youtube.com; домены видео могут потребовать отдельного списка.'],
        [/IP устройств|Источник|Входящ/i,'Это ограничение по устройству, от которого пришёл трафик. Вместе с доменами действует условие «И», а не «ИЛИ».','example.org И устройство 192.168.1.25. Для отдельного полного маршрута устройства создайте другую группу.'],
        [/CIDR|IP сет|IP назначения/i,'Правило сопоставляет адрес назначения или подсеть. CIDR задаёт диапазон адресов; при FakeIP известный движку адрес может отличаться от публичного.','192.168.1.25/32 — один IPv4 адрес; 192.168.1.0/24 — подсеть.'],
        [/FakeIP/i,'Включение выдаёт проксируемым доменам временные адреса: Atlas сохраняет имя сайта и выбирает группу. Если оставить выключенным, используются реальные IP, и несколько доменов на одном IP сложнее различать. Несовместимое с FakeIP приложение может перестать работать; внешний IP от этого переключателя не меняется.','Начните с FakeIP для доменных групп; при проблеме отдельного приложения проверьте его DNS и исключения.'],
        [/DNS|dnsmasq|resolver/i,'DNS переводит имена сайтов в IP. Выбранный DNS используется в указанном канале: основной — для сайтов, bootstrap — для адресов прокси. AdGuard DNS дополнительно фильтрует рекламные домены; Cloudflare не включает этот рекламный фильтр. Если оставить текущие значения, провайдер и способ запросов не изменятся.','Для автоматической блокировки рекламы нажмите «Включить AdGuard DNS». Настройки своего DNS нужны только при наличии его адреса и инструкции.'],
        [/Интервал|обновлен/i,'Интервал определяет желаемую частоту проверки или обновления. Фоновый выбор Atlas запускается планировщиком примерно раз в минуту и ограничивает число одновременных проверок.','60 секунд — обычный старт для автопроверки; подписку можно обновлять раз в несколько часов.'],
        [/задержк|пинг|Допустимая разница/i,'Задержка показывает время ответа тестового адреса. Небольшая разница не обязательно требует переключения; стабильность зависит также от потерь и доступности нужного сайта.','Допуск 80 мс уменьшает лишние переключения между близкими профилями.'],
        [/Стран|countries/i,'Название профиля может неверно указывать страну. Проверка страны измеряет выход конкретного профиля; строгий фильтр требует свежего подтверждения.','Разрешить DE и NL; непроверенные профили могут быть исключены строгим режимом.'],
        [/Кеш|хранени|Путь|Каталог/i,'Данные можно хранить в памяти или на постоянном накопителе. Память освобождается при перезагрузке; постоянная запись изнашивает flash.','Для NanoPi кеш в RAM сохраняет flash; резервные копии храните отдельно.'],
        [/Порт|TCP|UDP|Транспорт|QUIC/i,'Это дополнительное сетевое условие. QUIC использует UDP; блокировка UDP/443 заставляет совместимые приложения пробовать TCP, но не все приложения смогут переключиться.','HTTPS обычно использует TCP/443; QUIC — UDP/443.'],
        [/Файл|список|списки|community/i,'Список объединяет много доменов или сетей. Назначьте его нужной группе и проверьте последнее обновление. При ошибке Atlas сохраняет прежнюю рабочую копию.','Общественный список YouTube → группа YouTube → её собственный профиль.'],
        [/Выбор|профиль|резерв/i,'Автоматический режим выбирает подходящий профиль из набора. Ручной выбор фиксирует один профиль. Если проверки группы заданы, автоматический выбор требует их успеха.','Один профиль открывает YouTube, другой — HDRezka: создайте две группы с разными адресами проверки.'],
        [/Остальные|Режим|маршрут|Действие/i,'Маршрут определяет, где пойдёт совпавший трафик. В режиме групп остальные сайты идут напрямую. В глобальном режиме используется общий прокси, кроме исключений.','Только Видео через прокси, банковский сайт и остальной интернет напрямую.'],
        [/Пароль|заголовк|Имя пользователя/i,'Это данные доступа. Они сохраняются на роутере и могут входить в резервную копию. Не публикуйте их и не используйте обычный текст вместо защищённого поля пароля.','HTTP-заголовок Authorization нужен только если его требует провайдер подписки.'],
        [/Название/i,'Название помогает различать группы и подключения. Оно не задаёт маршрут: маршрут определяется доменами, списками и выбранным действием.','Видео, Работа, Игры.'],
        [/JSON/i,'Экспертная конфигурация для особых схем. Обычной настройке групп она не нужна. Ссылки на выходы и параметры проверяются перед применением.','Используйте мастер для стандартного маршрута; JSON нужен для нестандартной цепочки выходов.']
    ];
    var entry=entries.find(function(e){return e[0].test(title);});
    return {body:(hint ? hint+' ' : '')+(entry ? entry[1] : 'Этот параметр изменяет указанное поведение Atlas. Если базовая настройка работает, сначала сохраните резервную копию и меняйте по одному параметру, проверяя результат.'),example:entry ? entry[2] : 'Настройте отдельную группу для нужных сайтов, сохраните и проверьте маршрут перед применением.'};
}
function atlasHelpBox(title,hint) {
    var help=atlasHelp(title,hint);
    return atlasElement('details',{'class':'at-help'},[atlasElement('summary',{'aria-label':'Пояснение: '+title},'Что это и как выбрать?'),node('p','',label(help.body)),node('p','at-help-example',label('Пример: '+help.example))]);
}

return view.extend({
    tab: 'overview',
    search: '',
    monitor: null,
    load: function() { return result(api.status()); },
    handleSave: null,
    handleSaveApply: null,
    handleReset: null,
    render: function(data) {
        this.data = data;
        this.readonly = !L.hasViewPermission();
        this.root = node('div', 'atlas');
        this.draw();
        var self = this;
        poll.add(function() {
            var status = result(api.status());
            var monitor = self.tab === 'monitor' && !self.readonly ? self.requestMonitor().catch(function(e) {
                return { ok: true, available: false, message: e.message || 'Монитор недоступен', connections: [], rules: [] };
            }) : Promise.resolve(null);
            return Promise.all([status, monitor]).then(function(values) {
                var d = values[0];
                if (values[1]) self.monitor = values[1];
                var previous = self.data.job || {};
                self.data = d;
                self.offline = false;
                if (d.job && d.job.id && (d.job.status === 'done' || d.job.status === 'error') &&
                    (previous.id !== d.job.id || previous.status !== d.job.status)) {
                    ui.addNotification(null, node('p', '', label(d.job.message)), d.job.status === 'error' ? 'error' : 'info');
                }
                if (self.tab !== 'routing' && self.tab !== 'settings' && !self.searchFocused) self.draw();
            }).catch(function() {
                self.offline = true;
                if (self.tab !== 'routing' && self.tab !== 'settings') self.draw();
            });
        }, 4);
        return node('div', '', [atlasElement('link', { rel: 'stylesheet', href: L.resource('atlas/atlas.css') + '?v=adaptive-20261011-2' }), this.root]);
    },
    busy: function() { return this.offline || ['queued', 'running'].indexOf((this.data.job || {}).status) >= 0; },
    button: function(title, callback, kind, disabled) {
        var self = this;
        return node('button', 'at-btn ' + (kind || ''), label(title), {
            type: 'button', disabled: !!disabled || self.readonly,
            click: function(event) {
                var button = event.currentTarget;
                button.disabled = true;
                Promise.resolve().then(callback).catch(error).finally(function() { button.disabled = !!disabled || self.readonly; });
            }
        });
    },
    reload: function() {
        var self = this;
        return result(api.status()).then(function(d) { self.data = d; self.draw(); });
    },
    action: function(operation, id) {
        var self = this;
        return result(api.action(operation, id || '')).then(function() { return self.reload(); });
    },
    requestMonitor: function() {
        var self = this;
        if (!self.monitorRequest) self.monitorRequest = result(api.monitor()).finally(function() { self.monitorRequest = null; });
        return self.monitorRequest;
    },
    navigate: function(tab) {
        if (tab !== this.tab) this.sectionDashboardPanel = null;
        this.tab = tab;
        if (tab === 'monitor' && !this.readonly) {
            var self = this;
            self.requestMonitor().then(function(m) { self.monitor = m; if (self.tab === 'monitor') self.draw(); })
                .catch(function(e) { self.monitor = { available: false, message: e.message || 'Монитор недоступен', connections: [], rules: [] }; self.draw(); });
        }
        this.draw();
    },
    draw: function() {
        var self = this, d = self.data;
        self.disclosureState=self.disclosureState || {};
        if(self.renderedTab){var previous={};atlasDisclosures(self.root).forEach(function(x){previous[x.key]=!!x.element.open;});self.disclosureState[self.renderedTab]=previous;}
        var navigation = [ ['overview', '◈', 'Обзор'], ['subscriptions', '▤', 'Подключения'], ['nodes', '◎', 'Профили'], ['routing', '⇄', 'Маршрутизация'], ['privacy', '◉', 'Безопасность'] ];
        if (!self.readonly) navigation.push(['monitor', '⌁', 'Монитор соединений']);
        navigation.push(['settings', '⚙', 'Настройки']);
        var sidebar = node('aside', 'at-sidebar', [
            node('div', 'at-brand', [node('span', 'at-logo', label('a')), node('div', '', [node('strong', '', label('atlas')), node('small', '', label('OPENWRT · ROUTING'))])]),
            node('div', 'at-nav-label', label('РАБОЧЕЕ ПРОСТРАНСТВО')),
            node('nav', 'at-nav', navigation.map(function(n) {
                return node('button', self.tab === n[0] ? 'active' : '', [node('span', 'at-nav-icon', label(n[1])), label(n[2]), n[0] === 'subscriptions' ? node('small', '', label(d.subscriptions.length)) : label('')], {
                    type: 'button', 'aria-current': self.tab === n[0] ? 'page' : null,
                    click: function() { self.navigate(n[0]); }
                });
            })),
            node('div', 'at-sidebar-bottom', [node('span', 'at-dot ' + (d.running && !self.offline ? 'on' : '')), label(self.offline ? 'Связь потеряна' : d.running ? 'Движок запущен' : 'Движок остановлен'), node('small', '', label('Atlas ' + d.version + ' · beta'))])
        ]);
        var title = navigation.filter(function(n) { return n[0] === self.tab; })[0][2];
        var content = node('main', 'at-main', [
            node('header', 'at-topbar', [node('div', '', [node('span', 'at-crumb', label('Сеть / Atlas')), node('h1', '', label(title))]), self.button('Настроить по вопросам',function(){self.setupWizard();},'primary at-wizard-launch',self.busy())]),
            self.readonly ? node('div', 'at-notice', label('Режим чтения: изменения доступны администратору.')) : label(''),
            self.offline ? node('div', 'at-notice error', label('Нет связи с роутером. Показаны последние полученные данные.')) : label(''),
            !d.engine ? node('div', 'at-notice error', label('sing-box не найден. Установите движок версии 1.12 или новее.')) : label(''),
            ['queued','running'].indexOf((d.job || {}).status) >= 0 ? node('div', 'at-notice', [node('span', 'at-spinner'), label(d.job.message || 'Выполняется операция…')]) : label(''),
            self[self.tab + 'Page']()
        ]);
        self.root.replaceChildren(sidebar, content);
        var saved=self.disclosureState[self.tab] || {};
        atlasDisclosures(self.root).forEach(function(x){if(Object.prototype.hasOwnProperty.call(saved,x.key))x.element.open=saved[x.key];});
        self.renderedTab=self.tab;
    },
    sectionDashboard: function() {
        // Status polling redraws the overview. Keep its expanded section panel
        // and unsaved server selection until the user leaves this page.
        if (this.sectionDashboardPanel) {
            var disabled=this.busy() || this.readonly;
            this.sectionDashboardPanel.querySelectorAll('button').forEach(function(button){button.disabled=disabled;});
            return this.sectionDashboardPanel;
        }
        var self = this, panel = node('section', 'at-card at-padded', []);
        function load() { return result(api.sectionDashboard()).then(function(r) {
            panel.replaceChildren(node('h3', '', label('Серверы секций')), self.button('Обновить секции', load, 'ghost', self.busy()));
            (r.sections || []).forEach(function(section) {
                var card = node('div', 'at-padded', [node('h4', '', label(section.name))]);
                section.groups.forEach(function(group) {
                    var selection = node('select', 'at-input', group.members.map(function(m) { return atlasElement('option', {value:m.tag, selected:m.tag === group.selected}, m.name + (m.delay ? ' · ' + m.delay + ' мс' : '')); }));
                    card.appendChild(self.field(group.type === 'selector' ? 'Активный сервер' : 'Автоматическая группа', selection, group.shared ? 'Общий пул: выбор изменится во всех использующих его секциях.' : 'Независимый выход секции.'));
                    if (group.type === 'selector') card.appendChild(self.button('Выбрать сервер', function() { return result(api.sectionSelect(section.id, group.tag, selection.value)).then(load); }, 'ghost', self.busy()));
                    else selection.disabled = true;
                });
                if (section.groups.length) card.appendChild(self.button('Проверить задержки секции', function() { return self.action('section_test', section.id); }, 'ghost', self.busy()));
                else card.appendChild(node('p', 'at-footnote', label('В этой секции нет группы серверов.')));
                panel.appendChild(card);
            });
            if (r.message) panel.appendChild(node('p', 'at-footnote', label(r.message)));
        }); }
        panel.appendChild(node('h3','',label('Серверы секций')));
        panel.appendChild(self.button('Показать секции и серверы', load, 'ghost', self.busy()));
        self.sectionDashboardPanel = panel;
        return panel;
    },
    overviewPage: function() {
        var self = this, d = self.data, checks = d.checks || {};
        var measured = d.nodes.filter(function(n) { return checks[n.key] && checks[n.key].ok; });
        var healthy = measured.length;
        var selected = d.runtime && d.runtime.blocked ? (d.runtime.reason === 'no-main-pool' ? d.runtime.message : 'Заблокирован критериями выбора') : d.runtime && d.runtime.available && d.runtime.selected ? d.runtime.name : 'Выбор движка пока неизвестен';
        return node('div', 'at-content', [
            node('section','at-wizard-start',[node('div','',[node('span','at-start-label',label('НАЧНИТЕ ЗДЕСЬ')),node('h2','',label('Настроить Atlas по шагам')),node('p','',label('Ответьте на простые вопросы: какие сайты открывать через прокси, какое подключение использовать и как проверять серверы. В конце мастер покажет итог. До подтверждения маршруты не меняются.'))]),self.button('Настроить по вопросам',function(){self.setupWizard();},'primary at-wizard-launch',self.busy())]),
            node('section', 'at-hero', [
                node('div', 'at-hero-copy', [node('h2', '', label(d.running ? 'Atlas работает' : 'Atlas остановлен')),
                    node('p', '', label('Подключения → группы сайтов → проверка и применение. Мастер проведёт настройку по шагам.')),
                    node('div', 'at-actions', [self.button(d.running ? 'Применить изменения' : 'Запустить Atlas', function() { return self.action(d.running ? 'apply' : 'start'); }, 'primary', self.busy() || (!d.nodes.length && !(d.settings.remote_lists || []).some(function(x){return x.enabled !== false;}) && !(d.settings.sections || []).some(function(x) { return x.enabled !== false && (x.outbound_config_set || x.policy !== 'proxy'); }))),
                        d.running ? self.button('Остановить', function() { return self.action('stop'); }, 'ghost', self.busy()) : self.button('Добавить подписку', function() { self.subscriptionDialog(); }, 'ghost', self.busy())])]),
                node('div', 'at-orbit', [node('div', 'at-orbit-ring r1'), node('div', 'at-orbit-ring r2'), node('div', 'at-orbit-dot d1'), node('div', 'at-orbit-dot d2'), node('div', 'at-orbit-center', label('a'))], { 'aria-hidden': 'true' })
            ]),
            self.sectionDashboard(),
            node('section','at-card at-padded',[node('h3','',label('Автозапуск')),node('p','at-footnote',label(d.autostart ? 'Atlas включён для запуска после загрузки роутера.' : 'Автозапуск Atlas выключен.')),self.button(d.autostart ? 'Выключить автозапуск' : 'Включить автозапуск',function(){return result(api.setAutostart(!d.autostart)).then(function(){return self.reload();});},'ghost',self.busy()),node('p','at-footnote',label('Эта кнопка не запускает и не останавливает работающую службу. «Запустить Atlas» включает автозапуск; «Остановить» выключает его.'))]),
            node('div', 'at-stats', [
                self.stat('СОСТОЯНИЕ', d.runtime && d.runtime.blocked ? 'Пул заблокирован' : d.running ? 'Запущен' : 'Остановлен', d.running ? 'Процесс sing-box работает' : 'Трафик не перенаправляется', d.running ? 'green' : ''),
                self.stat('ПОДПИСКИ', String(d.subscriptions.length).padStart(2, '0'), d.subscriptions.filter(function(s) { return s.enabled; }).length + ' включено'),
                self.stat('СЕРВЕРЫ', String(d.nodes.length).padStart(2, '0'), healthy + ' прошли последнюю HTTPS проверку'),
                self.stat('МАРШРУТИЗАЦИЯ', d.settings.mode === 'rules' ? 'По правилам' : 'Весь трафик', (d.settings.sections || []).filter(function(x){return x.enabled !== false;}).length + ' секций · ' + (d.settings.remote_lists || []).filter(function(x){return x.enabled !== false;}).length + ' списков')
            ]),
            node('div', 'at-grid-2', [
                node('section', 'at-card', [self.sectionHead('Ваши подписки', 'Источники серверов', self.button('+ Добавить', function() { self.subscriptionDialog(); }, 'small', self.busy())),
                    d.subscriptions.length ? node('div', 'at-sub-list', d.subscriptions.slice(0, 3).map(function(s) { return self.subscriptionRow(s); })) : self.empty('Начните с подписки', 'Добавьте ссылку провайдера и нажмите «Обновить».', function() { self.subscriptionDialog(); }, 'Добавить подписку')]),
                node('section', 'at-card', [self.sectionHead('Путь трафика', 'Текущие настройки'),
                    node('div', 'at-route-visual', [node('div', 'at-route-step', [node('span', 'at-route-icon', label('⌂')), node('div', '', [node('strong', '', label('Ваша сеть')), node('small', '', label('Устройства за роутером'))])]),
                        node('div', 'at-route-line'), node('div', 'at-route-step', [node('span', 'at-route-icon purple', label('a')), node('div', '', [node('strong', '', label('Atlas')), node('small', '', label(d.settings.mode === 'rules' ? 'Проверка доменов и IP' : 'Все внешние назначения'))])]),
                        node('div', 'at-route-branches', [node('div', '', [pill('ТУННЕЛЬ', 'purple'), node('small', '', label(selected))]), node('div', '', [pill('НАПРЯМУЮ', 'neutral'), node('small', '', label('Локальная сеть и исключения'))])])]),
                    node('p', 'at-footnote', label('Состояние процесса не гарантирует доступ в интернет. Проверяйте серверы после обновления.'))])
            ]),
            node('div', 'at-bottom-note', [label('Последнее применение: ' + (d.applied.at ? date(d.applied.at) : 'ещё не применялось')), label('Автообновление каждые ' + d.settings.interval_hours + ' ч')])
        ]);
    },
    stat: function(title, value, sub, cls) { return node('article', 'at-stat ' + (cls || ''), [node('span', 'at-stat-title', label(title)), node('strong', '', label(value)), node('small', '', label(sub))]); },
    sectionHead: function(title, subtitle, action) { return node('div', 'at-section-head', [node('div', '', [node('h3', '', label(title)), subtitle ? node('p', '', label(subtitle)) : label('')]), action || label('')]); },
    empty: function(title, desc, cb, button) { return node('div', 'at-empty', [node('span', 'at-empty-icon', label('◈')), node('h3', '', label(title)), node('p', '', label(desc)), cb ? this.button(button, cb, 'primary', this.busy()) : label('')]); },
    subscriptionRow: function(s) {
        var self = this;
        return node('div', 'at-sub-row', [node('div', 'at-sub-icon', label('▤')), node('div', 'at-grow', [node('strong', '', label(s.name)), node('small', '', label(s.host + ' · ' + s.count + ' серверов'))]),
            pill(s.error ? 'Ошибка' : !s.enabled ? 'Выключена' : s.updated ? 'Обновлена' : 'Новая', s.error ? 'danger' : s.enabled && s.updated ? 'success' : 'neutral'),
            self.button('↻', function() { return self.action('refresh', s.id); }, 'icon', self.busy() || !s.enabled || s.source === 'local')]);
    },
    subscriptionsPage: function() {
        var self = this, d = self.data;
        return node('div', 'at-content', [self.sectionHead('Источники подключений', 'Ссылки хранятся на роутере и не передаются сторонним конвертерам.', node('div', 'at-actions', [self.button('Обновить все', function() { return self.action('refresh'); }, '', self.busy() || !(d.subscriptions.some(function(s) { return s.enabled && s.source !== 'local'; }) || (d.settings.remote_lists || []).some(function(x) { return x.enabled; }))), self.button('Импорт текста/JSON', function() { self.localProfilesDialog(); }, 'ghost', self.busy()), self.button('Массовый импорт', function() { self.bulkSubscriptionDialog(); }, 'ghost', self.busy()), self.button('+ Подписка', function() { self.subscriptionDialog(); }, 'primary', self.busy())])),
            d.subscriptions.length ? node('div', 'at-sub-grid', d.subscriptions.map(function(s) {
                var meta = s.metadata || {}, used = (meta.download || 0) + (meta.upload || 0);
                return node('article', 'at-card at-sub-card', [self.subscriptionRow(s),
                    node('dl', 'at-details', [node('dt', '', label('ID пула')), node('dd', '', label(s.id)), node('dt', '', label('Формат')), node('dd', '', label(s.format || 'Не определён')), node('dt', '', label('Обновлено')), node('dd', '', label(date(s.updated))), node('dt', '', label('Трафик')), node('dd', '', label(bytes(used) + (meta.total > 0 ? ' / ' + bytes(meta.total) : ' · лимит не указан'))), node('dt', '', label('Срок действия')), node('dd', '', label(meta.expire > 0 ? date(meta.expire) : 'Провайдер не указал'))]),
                    s.headers_set ? node('p', 'at-footnote', label('Для запроса настроены приватные HTTP-заголовки.')) : label(''),
                    s.change && Number.isFinite(s.change.added) && Number.isFinite(s.change.removed) && Number.isFinite(s.change.total) ? node('p', 'at-footnote', label('Изменение: +' + s.change.added + ' / −' + s.change.removed + ' профилей; всего ' + s.change.total + (s.change.unchanged ? ' · без изменений' : ''))) : label(''),
                    s.error ? node('p', 'at-inline-error', label(s.error)) : label(''),
                    (s.warnings || []).length ? node('p', 'at-inline-error', label('Пропущено узлов: ' + s.warnings.length + '. Проверьте формат у провайдера.')) : label(''),
                    node('div', 'at-actions at-card-footer', [s.source === 'local' ? self.button('Редактировать JSON', function() { return result(api.getProfiles(s.id)).then(function(r) { self.localProfilesDialog(s, r.content); }); }, '', self.busy()) : label(''), s.source === 'local' ? self.button(s.enabled ? 'Выключить' : 'Включить', function() { return result(api.saveSubscription(s.id, s.name, '', !s.enabled, '', false)).then(function() { return self.reload(); }); }, '', self.busy()) : self.button('Изменить', function() { self.subscriptionDialog(s); }, '', self.busy()), self.button('Удалить', function() { self.deleteDialog(s); }, 'danger-link', self.busy())])]);
            })) : self.empty('Все ваши подписки — здесь', 'Поддерживаются URI, Base64, Clash/Mihomo YAML и sing-box JSON.', function() { self.subscriptionDialog(); }, 'Добавить первую подписку'),
            node('p', 'at-footnote', label('До 64 источников, 512 профилей на источник и 4096 сохранённых профилей. Активный пул ограничен настройкой производительности (128–1024). Поддерживаются URI VLESS/VMess/Trojan/Shadowsocks/Hysteria2/TUIC/AnyTLS/SOCKS/HTTP, Clash/Mihomo YAML и sing-box JSON. Изменения профилей отображаются после обновления.'))]);
    },
    subscriptionDialog: function(sub) {
        var self = this; sub = sub || {};
        var name = node('input', 'at-input', [], { value: sub.name || '', placeholder: 'Например, основная подписка', maxlength: 80 });
        var url = node('input', 'at-input', [], { type: 'password', autocomplete: 'new-password', placeholder: sub.id ? 'Оставьте пустым, чтобы сохранить ссылку' : 'https://… или happ://crypt5/…' });
        var headers = node('textarea', 'at-input at-textarea', [], { rows: 4, autocomplete: 'off', spellcheck: 'false', placeholder: 'Authorization: Bearer …\nUser-Agent: …' });
        var clearHeaders = node('input', '', [], { type: 'checkbox' });
        var enabled = node('input', '', [], { type: 'checkbox', checked: sub.enabled !== false });
        var msg = node('p', 'at-inline-error');
        ui.showModal(sub.id ? 'Изменить подписку' : 'Новая подписка', [node('div', 'at-modal', [self.field('Название', name), self.field('Ссылка подписки', url), self.field('HTTP-заголовки провайдера', headers), sub.headers_set ? node('p', 'at-footnote', label('Заголовки уже сохранены и скрыты. Пустое поле сохраняет их; новые строки заменят их.')) : label(''), node('label', 'at-checkbox', [clearHeaders, label('Удалить сохранённые заголовки')]), node('label', 'at-checkbox', [enabled, label('Использовать подписку')]), msg,
            node('p', 'at-footnote', label('Заголовки хранятся только на роутере с настройками Atlas. Перенаправление на другой сервер запрещено, чтобы не переслать токен. После сохранения нажмите «Обновить».'))]), node('div', 'right', [atlasElement('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Сохранить', function() {
                return result(api.saveSubscription(sub.id || '', name.value, url.value, enabled.checked, headers.value, clearHeaders.checked)).then(function() { ui.hideModal(); return self.reload(); }).catch(function(e) { msg.textContent = e.message; });
            }, 'primary')])]);
    },
    bulkSubscriptionDialog: function() {
        var self = this;
        var content = node('textarea', 'at-input at-textarea', [], { rows: 10, spellcheck: 'false', placeholder: 'https://provider.example/sub/…\nРезерв | https://backup.example/sub/…\nhttps://provider.example/another' });
        var msg = node('div', 'at-bulk-results');
        ui.showModal('Массовый импорт подписок', [node('div', 'at-modal', [self.field('Одна HTTPS или Happ-ссылка на строку; можно «название | ссылка»', content), msg,
            node('p', 'at-footnote', label('Atlas сохранит до 64 источников, проверит URL и удалит дубликаты. Профили будут загружены после «Обновить все». Для авторизованных источников добавьте заголовки отдельно в настройках каждой подписки.'))]),
            node('div', 'right', [atlasElement('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Добавить источники', function() {
                var items = [];
                try {
                    items = content.value.split(/\r?\n/).map(function(line) { return line.trim(); }).filter(Boolean).map(function(line, index) {
                        var parts = line.split('|');
                        if (parts.length > 2) throw new Error('Строка ' + (index + 1) + ': используйте формат «название | ссылка»');
                        return parts.length === 2 ? { name: parts[0].trim(), url: parts[1].trim() } : { name: '', url: line.trim() };
                    });
                    if (!items.length || items.length > 64) throw new Error('Укажите от 1 до 64 строк');
                } catch (e) { msg.textContent = e.message; return Promise.resolve(); }
                return result(api.importSubscriptions(items)).then(function(r) {
                    msg.replaceChildren(node('p', '', label('Добавлено: ' + r.added + ' · дубликаты: ' + r.duplicates + ' · ошибки: ' + r.errors)));
                    if (r.items && r.items.length) msg.appendChild(node('ul', 'at-bulk-list', r.items.map(function(x) { return node('li', '', label(x.line + '. ' + x.name + ' — ' + (x.status === 'added' ? 'добавлено' : x.status === 'duplicate' ? 'уже есть' : x.message))); })));
                    return self.reload();
                }).catch(function(e) { msg.textContent = e.message; });
            }, 'primary')])]);
    },
    localProfilesDialog: function(source, initialContent) {
        var self = this; source = source || {};
        var name = node('input', 'at-input at-local-name', [], { value: source.name || 'Локальные профили', maxlength: 80 });
        var content = node('textarea', 'at-input at-textarea at-local-profiles', label(initialContent || ''), { rows: 12, spellcheck: 'false', placeholder: 'vless://…\nИли вставьте Base64, Clash/Mihomo YAML, sing-box JSON' });
        var msg = node('p', 'at-inline-error');
        ui.showModal(source.id ? 'Редактирование локальных профилей' : 'Импорт профилей из текста', [node('div', 'at-modal', [self.field('Название источника', name), self.field('Профили или конфигурация', content), msg,
            node('p', 'at-footnote', label('До 256 КиБ и 512 профилей. Atlas проверит конфигурацию через sing-box до сохранения. Локальный источник не загружается из сети. Для изменения рабочего туннеля примените настройки.'))]),
            node('div', 'right', [atlasElement('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Импортировать профили', function() {
                return result(api.importProfiles(name.value.trim(), content.value, source.id || '')).then(function(r) {
                    ui.hideModal();
                    ui.addNotification(null, node('p', '', label('Импортировано профилей: ' + r.count + ((r.warnings || []).length ? ' · пропущено: ' + r.warnings.length : ''))), 'info');
                    return self.reload();
                }).catch(function(e) { msg.textContent = e.message; });
            }, 'primary')])]);
    },
    deleteDialog: function(sub) {
        var self = this;
        ui.showModal('Удалить подписку?', [node('p', '', label('«' + sub.name + '» и её сохранённые серверы будут удалены. Для изменения работающего туннеля примените настройки.')),
            node('div', 'right', [atlasElement('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Удалить', function() { return result(api.deleteSubscription(sub.id)).then(function() { ui.hideModal(); return self.reload(); }); }, 'danger')])]);
    },
    nodesPage: function() {
        var self = this, d = self.data, checks = d.checks || {};
        var search = node('input', 'at-input at-search', [], { placeholder: 'Поиск сервера или подписки…', value: self.search, 'aria-label': 'Поиск сервера', focus: function() { self.searchFocused = true; }, blur: function() { self.searchFocused = false; } });
        var container = node('div', 'at-table-wrap');
        function table() {
            var list = d.nodes.filter(function(n) { return (n.name + ' ' + n.subscription).toLowerCase().indexOf(self.search.toLowerCase()) >= 0; });
            container.replaceChildren(node('table', 'at-table', [node('thead', '', node('tr', '', ['Сервер', 'Протокол', 'Страна выхода', 'Подписка', 'HTTPS проверка', 'Выбор'].map(function(t) { return node('th', '', label(t)); }))),
                node('tbody', '', list.map(function(n) {
                    var c = checks[n.key];
                    return node('tr', d.runtime && d.runtime.selected === n.key ? 'selected' : '', [node('td', '', [node('strong', '', label(n.name)), node('small', '', label(n.server + ':' + n.port)), n.eligible === false ? pill('Исключён фильтром', 'neutral') : label(''), d.runtime && d.runtime.selected === n.key ? pill('Используется движком', 'success') : label('')]), node('td', '', pill(n.type.toUpperCase(), 'neutral')), node('td', '', [node('strong', '', label(n.country || 'Неизвестна')), node('small', '', label(n.country_source === 'exit-ip' ? 'Проверена по IP · ' + date(n.country_verified_at) : 'Метка провайдера')), self.button('Проверить IP выхода', function() { return self.action('geo_check', n.key); }, 'small', self.busy())]), node('td', '', label(n.subscription)), node('td', '', [pill(!c ? 'Не проверен' : c.ok ? c.latency_ms + ' мс' : c.stage === 'engine' ? 'Не удалось проверить' : 'Не прошёл', !c || c.stage === 'engine' ? 'neutral' : c.ok ? 'success' : 'danger'), c ? node('small', '', label(date(c.checked))) : label(''), c && c.error ? node('small', '', label(c.error)) : label('')]), node('td', '', self.button(d.settings.selected === n.key ? 'Выбран' : 'Выбрать', function() { var s = Object.assign({}, d.settings, { selected: n.key }); return result(api.saveSettings(s)).then(function() { return d.running ? self.action('apply') : self.reload(); }); }, 'small', self.busy() || n.eligible === false || d.settings.selected === n.key))]);
                }))]));
            if (!list.length) container.appendChild(self.empty('Серверов нет', d.nodes.length ? 'Попробуйте другой запрос.' : 'Добавьте и обновите подписку.'));
        }
        search.addEventListener('input', function() { self.search = search.value; table(); }); table();
        var eligible = d.nodes.filter(function(n) { return n.eligible !== false; }).length;
        var runtime = d.runtime || {};
        return node('div', 'at-content', [self.sectionHead('Доступные серверы', 'HTTPS проверка выполняется через узлы, прошедшие фильтры.', self.button('Проверить серверы', function() { return self.action('probe'); }, 'primary', self.busy() || !eligible)),
            node('p', 'at-footnote', label('Проверка страны выполняет HTTPS запрос через выбранный профиль к ipapi.co. Сервис видит выходной IP; Atlas сохраняет только код страны и время. При изменении страны фильтры применяются заново; если допустимых серверов нет, туннель останавливается с fail-closed.')),
            node('div', 'at-auto-card', [node('div', '', [node('strong', '', label('Автовыбор и фильтры')), node('p', '', label('Пинг: ' + (d.settings.auto_strategy || 'fastest') + ' · допущено ' + eligible + ' из ' + d.nodes.length)), node('p', '', label('Разрешённые страны: ' + ((d.settings.countries || []).join(', ') || 'все') + ' · исключены: ' + ((d.settings.excluded_countries || []).join(', ') || 'нет') + ' · ' + (d.settings.selected === 'auto' ? 'автоматический режим' : 'ручной выбор')))]), self.button('Настроить автовыбор', function() { self.autoDialog(); }, '', self.busy())]),
            node('section', 'at-card at-padded', [node('h3', '', label('Фактически выбран движком')), node('p', 'at-runtime-name', label(runtime.available && runtime.selected ? runtime.name : runtime.message || 'Данные движка недоступны')), runtime.selected ? node('p', 'at-footnote', label((runtime.automatic || d.settings.selected === 'auto' ? 'Автоматический режим' : 'Вручную') + ' · в активной группе: ' + runtime.candidate_count + (runtime.last_delay_ms ? ' · последний замер: ' + runtime.last_delay_ms + ' мс (' + runtime.last_check + ')' : ''))) : label(''), node('p', 'at-footnote', label('Выбор узла сам по себе не подтверждает доступность соединения. После изменения настроек активная группа обновляется при применении.'))]),
            node('section', 'at-card at-padded', [node('h3', '', label('Пулы подписок')), node('div', '', (runtime.groups || []).map(function(g) { var sub = d.subscriptions.find(function(x) { return 'pool_' + x.id === g.group; }); return node('p', 'at-footnote', label((sub ? sub.name : g.group) + ': ' + g.name)); }))]),
            eligible === 1 ? node('p', 'at-inline-error', label('Фильтры оставили один узел. При его отказе переключаться не на что; другая страна автоматически не добавится.')) : label(''),
            search, container, node('p', 'at-footnote', label('Поиск в таблице меняет только отображение. Фильтры реально ограничивают группу выбора. Страна берётся из названия провайдера, не из геолокации выходного IP. После ручного выбора примените изменения в обзоре.'))]);
    },
    autoDialog: function() {
        var self = this, s = self.data.settings;
        var countries = node('input', 'at-input', [], { value: (s.countries || []).join(', '), placeholder: 'EE, DE — пусто означает все страны' });
        var excludedCountries = node('input', 'at-input', [], { value: (s.excluded_countries || []).join(', '), placeholder: 'RU — исключить профили из России' });
        var preferredCountries = node('input', 'at-input', [], { value: (s.preferred_countries || []).join(', '), placeholder: 'EE, DE — приоритет по порядку' });
        var verifiedCountries = node('input', 'at-verified-countries', [], { type: 'checkbox', checked: !!s.require_verified_countries });
        var protocols = node('input', 'at-input', [], { value: (s.protocols || []).join(', '), placeholder: 'vless, trojan — пусто означает все протоколы' });
        var include = node('input', 'at-input', [], { value: (s.include_names || []).join(', '), placeholder: 'Например: Hostslim' });
        var exclude = node('input', 'at-input', [], { value: (s.exclude_names || []).join(', '), placeholder: 'Например: test, backup' });
        var interval = node('input', 'at-input', [], { type: 'number', min: 30, max: 1800, value: s.auto_interval_seconds || 60 });
        var tolerance = node('input', 'at-input', [], { type: 'number', min: 1, max: 2000, value: s.auto_tolerance_ms || 80 });
        var minPing = node('input', 'at-input', [], { type: 'number', min: 0, max: 60000, value: s.min_ping_ms || 0 });
        var maxPing = node('input', 'at-input', [], { type: 'number', min: 0, max: 60000, value: s.max_ping_ms || 0 });
        var strategy = node('select', 'at-input', [atlasElement('option', { value: 'fastest', selected: (s.auto_strategy || 'fastest') === 'fastest' }, 'Минимальный пинг'), atlasElement('option', { value: 'slowest', selected: s.auto_strategy === 'slowest' }, 'Максимальный пинг'), atlasElement('option', { value: 'stable', selected: s.auto_strategy === 'stable' }, 'Наиболее стабильный пинг')]);
        var extensions = self.urltestExtensions(s);
        var testUrl = node('input', 'at-input', [], { value: s.urltest_url || 'https://www.gstatic.com/generate_204', placeholder: 'https://www.gstatic.com/generate_204' });
        var interrupt = node('input', '', [], { type: 'checkbox', checked: !!s.interrupt_connections });
        var msg = node('p', 'at-inline-error');
        ui.showModal('Автовыбор и фильтры серверов', [node('div', 'at-modal', [
            node('div', 'at-actions', [self.button('Только Эстония', function() { countries.value = 'EE'; }), self.button('Все страны', function() { countries.value = ''; })]),
            self.field('Страны', countries, 'Коды стран: EE — Эстония. Проверенная страна IP имеет приоритет над названием провайдера.'),
            self.field('Исключить страны', excludedCountries, 'Например RU. Исключённые страны никогда не попадают в auto пул.'),
            self.field('Предпочесть страны', preferredCountries, 'Порядок важен: EE, DE сначала выберет Эстонию, затем Германию.'),
            node('label', 'at-checkbox', [verifiedCountries, label('Для фильтров стран использовать только проверенный IP выхода')]),
            node('p', 'at-footnote', label('Проверьте нужные серверы в таблице перед включением. Результат действует 30 дней. Непроверенные страны исключаются при заданном фильтре.')),
            self.field('Критерий пинга', strategy, 'Критерии применяются отдельно к общему пулу и каждому пулу подписки. Atlas пересматривает выбор раз в минуту по свежим измерениям sing-box.'),
            node('div', 'at-grid-2', [self.field('Минимальный пинг, мс', minPing, '0 — без минимума.'), self.field('Максимальный пинг, мс', maxPing, '0 — без максимума; профили выше порога исключаются.')]),
            self.field('HTTPS адрес для проверки пинга', testUrl, 'Измеряется TLS/HTTP ответ через каждый прокси.'), extensions.element,
            self.field('Протоколы', protocols, 'vless, vmess, trojan, shadowsocks, hysteria2, tuic, socks, http'),
            self.field('Название содержит', include, 'Оставить только профили с указанным текстом в названии. Например LTE — останутся только LTE. Несколько значений через запятую: достаточно любого совпадения. Регистр не важен. Пусто — разрешить все названия.'),
            self.field('Исключить по названию', exclude, 'Например LTE — все профили с LTE в названии исключаются из доступного пула и автовыбора, остальные остаются. Регистр не важен; ищется часть названия, без регулярных выражений. Исключение имеет приоритет над полем «Название содержит». Пусто — никого не исключать.'),
            self.field('Проверять каждые, секунд', interval), self.field('Порог улучшения задержки, мс', tolerance, 'Уменьшает переключения при небольших колебаниях. Недоступный узел не удерживается этим порогом.'),
            node('label', 'at-checkbox', [interrupt, label('Разрывать текущие соединения при переключении')]),
            node('p', 'at-footnote', label('Обычно выключено: новые соединения идут через выбранный узел, текущие сохраняются. Включение может прервать звонки и загрузки. После 30 минут простоя проверки приостанавливаются до нового трафика.')),
            node('p', 'at-footnote', label('При нестандартных критериях группа блокируется до свежего подходящего замера; фильтры не расширяются. Для регулярных замеров без трафика через группу нужен Atlas Engine r2 или новее; возможность urltest.background показана ниже. Переключение разрывает старые соединения. FakeIP сохраняется в кеше; сохранённый выбор узла изолируется при каждом запуске службы.')), msg]),
            node('div', 'right', [atlasElement('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button(self.data.running ? 'Включить авто и применить' : 'Сохранить автовыбор', function() {
                var settings = Object.assign({}, s, { selected: 'auto', countries: lines(countries.value), excluded_countries: lines(excludedCountries.value), preferred_countries: lines(preferredCountries.value), require_verified_countries: verifiedCountries.checked, auto_strategy: strategy.value, min_ping_ms: Number(minPing.value), max_ping_ms: Number(maxPing.value), urltest_url: testUrl.value.trim(), protocols: lines(protocols.value), include_names: lines(include.value), exclude_names: lines(exclude.value), auto_interval_seconds: Number(interval.value), auto_tolerance_ms: Number(tolerance.value), interrupt_connections: interrupt.checked }, extensions.values());
                return result(api.saveSettings(settings)).then(function() { ui.hideModal(); return self.data.running ? self.action('apply') : self.reload(); }).catch(function(e) { msg.textContent = e.message; error(e); });
            }, 'primary')])]);
    },
    urltestExtensions: function(settings) {
        var self=this, features=self.data.engine_features || [], reserves=(settings.urltest_fallbacks || []).slice(), list=node('div','at-urltest-reserves',[]);
        function redraw() {
            list.replaceChildren();
            reserves.forEach(function(key,index) {
                var select=node('select','at-input',[]);
                function compact() {
                    var selected=reserves[index], member=(self.data.nodes || []).find(function(n){return n.key===selected;});
                    select.replaceChildren(atlasElement('option',{value:selected,selected:true},member ? member.name : 'Сохранённый профиль недоступен'));
                }
                compact();
                select.addEventListener('focus',function(){select.replaceChildren();(self.data.nodes || []).forEach(function(n){select.appendChild(atlasElement('option',{value:n.key,selected:n.key===reserves[index]},n.name));});if (!(self.data.nodes || []).some(function(n){return n.key===reserves[index];})) select.appendChild(atlasElement('option',{value:reserves[index],selected:true},'Сохранённый профиль недоступен'));});
                select.addEventListener('blur',compact);
                select.addEventListener('change',function(){reserves[index]=select.value;});
                list.appendChild(node('div','at-actions',[select,self.button('Выше',function(){if(index){var value=reserves[index-1];reserves[index-1]=reserves[index];reserves[index]=value;redraw();}},'ghost',index===0),self.button('Убрать',function(){reserves.splice(index,1);redraw();},'ghost')]));
            });
        }
        redraw();
        var mode=node('select','at-input at-download-mode',[atlasElement('option',{value:'default'},'Настройка движка'),atlasElement('option',{value:'off',disabled:features.indexOf('urltest.download_url')<0},'Выключено'),atlasElement('option',{value:'custom',disabled:features.indexOf('urltest.download_url')<0},'Свой адрес')]);
        mode.value=settings.urltest_download_check || 'default';
        var url=node('input','at-input at-download-url',[],{value:settings.urltest_download_url || '',placeholder:'https://example.com/test.bin'});
        var element=atlasElement('details',{},[atlasElement('summary',{},'Резервные серверы и проверка скачивания'),node('p','at-footnote',label('Резерв используется по порядку, когда нет основного сервера, подходящего по свежим замерам и вашим критериям. После восстановления группа возвращается к основным. Резервные серверы совместимы с приоритетом стран и порогами пинга. Проверка скачивания совместно с критериями Atlas требует Atlas Engine r3; перед переключением проверяется передача 64 КиБ через выбранный сервер. Для расширений нужен Atlas Engine.')),list,self.button('Добавить резервный сервер',function(){var available=(self.data.nodes || []).find(function(n){return reserves.indexOf(n.key)<0;});if(available){reserves.push(available.key);redraw();}},'ghost',features.indexOf('urltest.fallbacks')<0),self.field('Проверка скачивания 64 КиБ перед переключением',mode),self.field('Адрес файла для проверки',url),node('p','at-footnote',label('Расширения установленного движка: '+(features.join(', ') || 'не обнаружены')+'. Штатный sing-box сохраняет прежнее поведение. Сохранённые неподдерживаемые настройки требуют совместимого движка или очистки.'))]);
        return {element:element,values:function(){return {urltest_fallbacks:reserves.slice(),urltest_download_check:mode.value,urltest_download_url:mode.value==='custom' ? url.value.trim() : ''};}};
    },
    field: function(title,input,hint) { var help=atlasHelpBox(title,hint);if(input.setAttribute)input.setAttribute('aria-label',title);if(input.addEventListener)input.addEventListener('change',function(){help.open=true;});return node('div','at-field',[node('span','',label(title)),input,hint ? node('small','',label(hint)) : label(''),help]); },

    cloneSectionDialog: function(section) {
        var self=this,name=node('input','at-input at-clone-name',[],{value:(section.name+' копия').slice(0,48),maxlength:48});
        ui.showModal('Копировать сохранённую секцию',[atlasElement('button',{class:'btn',click:ui.hideModal},'Отмена'),self.field('Новое название',name),node('p','at-footnote',label('Будет скопирована последняя сохранённая версия. Копия выключена, имеет новый ID и не открывает прокси-порт. Несохранённые изменения формы не входят в копию.')),self.button('Создать копию',function(){return result(api.sectionClone(section.id,name.value.trim())).then(function(){ui.hideModal();return self.reload();});},'primary',self.busy())]);
    },
    plannerCard: function() {
        var self=this;
        function preview(validate){return result(api.configPreview(validate)).then(function(r){self.jsonDownloadDialog(validate?'Конфигурация проверена движком':'Предпросмотр конфигурации','atlas-config-preview.json',r.config,'Показаны сохранённые настройки. Секреты и произвольные поля протоколов скрыты. Служба и настройки не изменены. '+(r.conflicts.length ? 'Найдены перекрытия: '+r.conflicts.map(function(x){return x.section+' → '+x.earlier+' ('+x.domain+')';}).join('; ') : 'Перекрытия не найдены в первых 1000 простых доменных правил. Сложные правила и SRS требуют отдельной проверки.'));});}
        return node('section','at-card at-padded',[node('h3','',label('Проверка до применения')),node('p','at-footnote',label('Работает с сохранёнными настройками. Просмотрите конфигурацию, проверьте её установленным sing-box или объясните маршрут без сетевых запросов и перезапуска.')),node('div','at-actions',[self.button('Предпросмотр конфигурации',function(){return preview(false);},'ghost',self.busy()),self.button('Проверить без применения',function(){return preview(true);},'ghost',self.busy()),self.button('Объяснить маршрут',function(){self.routeExplainDialog();},'primary',self.busy())])]);
    },
    routeExplainDialog: function() {
        var self=this,fields={};
        [['domain','Домен','example.org'],['ip','Известный IP назначения','1.1.1.1'],['source_ip','IP устройства','192.168.1.25'],['port','Порт','443'],['inbound','Вход sing-box','tun']].forEach(function(x){fields[x[0]]=node('input','at-input at-explain-'+x[0],[],{value:x[0]==='port'?'443':x[0]==='inbound'?'tun':'',placeholder:x[2]});});
        var network=node('select','at-input at-explain-network',[atlasElement('option',{value:'tcp'},'TCP'),atlasElement('option',{value:'udp'},'UDP')]);
        var protocol=node('select','at-input at-explain-protocol',['tls','http','dns','quic',''].map(function(x){return atlasElement('option',{value:x},x||'Неизвестен');}));
        var output=node('div','at-explain-result');
        ui.showModal('Объяснение маршрута',[atlasElement('button',{class:'btn',click:ui.hideModal},'Закрыть'),node('div','at-grid-2',Object.keys(fields).map(function(k){return self.field({domain:'Домен',ip:'IP назначения',source_ip:'IP устройства',port:'Порт',inbound:'Вход'}[k],fields[k]);}).concat([self.field('Транспорт',network),self.field('Распознанный протокол',protocol)])),node('p','at-footnote',label('Это разбор правил, а не сетевой тест. Для точного результата укажите известные IP и протокол. Без них и при бинарном SRS ответ может быть неопределённым.')),output,self.button('Показать маршрут',function(){var query={network:network.value,protocol:protocol.value};Object.keys(fields).forEach(function(k){if(fields[k].value.trim())query[k]=k==='port'?Number(fields[k].value):fields[k].value.trim();});return result(api.routeExplain(query)).then(function(r){output.replaceChildren(node('strong','',label(r.certain ? 'Маршрут: '+(r.action==='reject'?'Блокировать':r.outbound) : 'Неопределённо: не хватает данных для предыдущих правил')),node('pre','',label(JSON.stringify(r.trace,null,2))));});},'primary',self.busy())]);
    },

    siteCheckFields: function(section) {
        var self=this, rows=(section.site_checks || []).map(function(c){return Object.assign({},c);}), holder=node('div','at-site-checks');
        function redraw(){holder.replaceChildren.apply(holder,rows.map(function(c,index){
            var url=node('input','at-input at-site-url',[],{value:c.url || '',placeholder:'https://www.youtube.com/',type:'url'});
            var statuses=node('input','at-input at-site-statuses',[],{value:(c.statuses || [200]).join(', '),placeholder:'200'});
            var marker=node('input','at-input at-site-marker',[],{value:c.contains || '',placeholder:'Необязательно: название сайта на странице'});
            url.addEventListener('input',function(){c.url=url.value;});statuses.addEventListener('input',function(){c.statuses=lines(statuses.value).map(Number);});marker.addEventListener('input',function(){c.contains=marker.value;});
            return node('div','at-site-row',[self.field('Адрес сайта для проверки',url,'Откройте этот адрес в браузере и скопируйте окончательный HTTPS URL после перенаправления.'),node('div','at-grid-2',[self.field('Успешные HTTP ответы',statuses,'Обычно 200; для пустого тестового ответа — 204. Ответ 403 не считается успехом.'),self.field('Текст, который должен быть на странице',marker,'Дополнительная проверка в первых 64 КиБ. Помогает отличить сайт от заглушки. Проверка страницы не доказывает воспроизведение видео.')]),self.button('Убрать проверку',function(){rows.splice(index,1);redraw();},'danger-link')]);
        }));}
        redraw();
        return {element:node('section','at-site-editor',[node('h3','',label('Какие сайты должны работать через этот профиль?')),node('p','at-footnote',label('Atlas проверяет каждый кандидат отдельно. Для группы YouTube укажите страницу YouTube; для другой группы — её сайт. Все заданные проверки должны пройти. Если подходящего профиля нет, эта группа блокируется, а не переходит напрямую. До трёх сайтов; периодический перебор выполняется ограниченными порциями.')),holder,self.button('+ Проверка сайта',function(){if(rows.length<3){rows.push({url:'',statuses:[200],contains:''});redraw();}},'ghost')]),values:function(){return rows.map(function(c){return {url:(c.url || '').trim(),statuses:c.statuses || [200],contains:c.contains || ''};});}};
    },
    sectionLayout: function(content) {
        var connection=[],targets=[],sources=[],exceptions=[],extras=[],errors=[];
        Array.from(content.children).forEach(function(child){
            var text=child.textContent || '',cls=child.getAttribute ? child.getAttribute('class') || '' : child.attributes && child.attributes.class || '';
            if(cls.indexOf('at-inline-error')>=0)errors.push(child);
            else if(cls.indexOf('at-section-sources-editor')>=0)sources.push(child);
            else if(text.indexOf('Исключения только из этой секции')===0)exceptions.push(child);
            else if(cls.indexOf('at-grid-2')>=0 && text.indexOf('Домены')===0){var primary=[],extra=[];Array.from(child.children).forEach(function(field,index){(index<3 ? primary : extra).push(field);});targets.push(node('div','at-grid-2',primary));extras.push(node('div','at-grid-2',extra));}
            else if(/^(Название|Группа включена|Действие|Подключение для группы|Исходящий VPN-интерфейс)/.test(text))connection.push(child);
            else extras.push(child);
        });
        content.replaceChildren.apply(content,[node('section','at-section-step',[node('h3','',label('1. Подключение и профили')),node('p','at-footnote',label('Выберите маршрут и подписку с профилями. Для прямого подключения или блокировки профиль не нужен.')),node('div','',connection)]),node('section','at-section-step',[node('h3','',label('2. Домены и IP этой секции')),node('p','at-footnote',label('Внутри поля записи означают «любая из перечисленных». Разные заполненные поля ограничивают друг друга: домен И IP устройства. Для независимых условий создайте отдельные секции. Пустые поля не ограничивают маршрут.')),node('div','',targets)]),node('section','at-section-step',sources),node('section','at-section-step',exceptions),atlasElement('details',{'class':'at-advanced'},[atlasElement('summary',{},'Автопроверка профилей и дополнительные параметры'),node('div','',extras)])].concat(errors));
        return content;
    },
    routingLayout: function(content) {
        var self=this,basic=[],advanced=[];
        Array.from(content.children).forEach(function(child){
            var text=child.textContent || '', cls=child.getAttribute ? child.getAttribute('class') || '' : child.attributes && child.attributes.class || '';
            if(text.indexOf('Куда направлять трафик')===0 || text.indexOf('Режим маршрутизации')===0 || text.indexOf('Секции: подключение')===0 || cls==='at-actions')basic.push(child);else advanced.push(child);
        });
        var guide=node('section','at-card at-padded at-guide',[node('h3','',label('Одна секция — одно подключение и его списки')),node('p','at-footnote',label('Откройте «Настроить секцию»: подключение, свои домены и IP, готовые и внешние списки собраны вместе. Мастер поможет создать первую секцию. Изменения сначала попадают в форму; затем нажмите «Сохранить и применить».')),self.button('Настроить по вопросам',function(){self.setupWizard();},'primary',self.busy()),node('p','at-footnote',label(self.data.settings.group_order ? 'Группы проверяются сверху вниз вместе со своими списками. Первое совпадение определяет маршрут; глобальные исключения остаются выше.' : 'Сохранён прежний порядок правил. Мастер предложит явный порядок групп; перед применением просмотрите итог.'))]);
        content.replaceChildren.apply(content,[guide].concat(basic,[atlasElement('details',{'class':'at-advanced'},[atlasElement('summary',{},'Дополнительные правила, списки и диагностика'),node('div','at-content at-advanced-content',advanced)])]));
        return content;
    },
    wizardWait: function() {
        var self=this,deadline=Date.now()+120000;
        function wait(){return result(api.status()).then(function(d){self.data=d;var job=d.job || {};if(job.status==='error')throw new Error(job.message || 'Операция не завершилась');if(['queued','running'].indexOf(job.status)<0)return d;if(Date.now()>deadline)throw new Error('Обновление ещё выполняется. Дождитесь его завершения и повторите сохранение группы.');return new Promise(function(resolve){setTimeout(resolve,900);}).then(wait);});}
        return wait();
    },
    setupWizard: function() {
        var self=this,s=self.data.settings,step=0,enabled=(self.data.subscriptions || []).filter(function(x){return x.enabled;}),draft={name:'Новая группа',source:enabled.length ? enabled[0].id : 'new',sourceName:'Новое подключение',sourceURL:'',domains:'',preset:'custom',policy:'proxy',selection:'auto',profile:'',testURL:'',marker:'',interval:60,mode:s.mode || 'rules',fakeip:!!s.fakeip,dhcp:!!s.dhcp_dns_enabled};
        var busy=false,saved=false,msg=node('p','at-inline-error'),collect=function(){};
        function input(key,placeholder,type){var n=node('input','at-input at-wizard-'+key,[],{value:draft[key],placeholder:placeholder || '',type:type || 'text'});n.addEventListener('input',function(){draft[key]=n.value;});return n;}
        function select(key,options){var n=node('select','at-input at-wizard-'+key,options.map(function(o){return atlasElement('option',{value:o[0],selected:draft[key]===o[0]},o[1]);}));n.addEventListener('change',function(){draft[key]=n.value;});return n;}
        function draw(){
            var body=[], titles=['Откуда брать профили?','Какие сайты объединить?','Куда направлять эту группу?','Как выбирать работающий профиль?','Как обрабатывать DNS и остальные сайты?','Проверьте итог перед сохранением'];
            msg=node('p','at-inline-error');collect=function(){};
            if(step===0){var sourcePicker=select('source',enabled.map(function(x){return [x.id,x.name+' · '+x.count+' профилей'];}).concat([['new','Добавить ссылку подписки'],['none','Без подключения: напрямую или блокировать']]));sourcePicker.addEventListener('change',draw);body=[self.field('Подключение',sourcePicker)];if(draft.source==='new')body.push(self.field('Название нового подключения',input('sourceName','Например, домашняя подписка')),self.field('Ссылка новой подписки',input('sourceURL','https://provider.example/sub','password')));body.push(node('p','at-footnote',label('Подписка — ссылка провайдера, из которой Atlas получает профили. Она сохраняется на роутере. Для прямого маршрута или блокировки выберите «Без подключения». Для отдельных URI сначала используйте импорт в «Подключениях».')));collect=function(){if(draft.source==='new' && (!draft.sourceName.trim() || !/^https:\/\//.test(draft.sourceURL)))throw new Error('Для новой подписки нужны название и HTTPS ссылка');};}
            if(step===1){var domains=node('textarea','at-input at-textarea at-wizard-domains',label(draft.domains),{rows:5,placeholder:'example.org\nexample.net'});domains.addEventListener('input',function(){draft.domains=domains.value;});var preset=select('preset',[['custom','Мои сайты'],['youtube','YouTube'],['hdrezka','HDRezka — список актуальных доменов']]);preset.addEventListener('change',function(){if(preset.value==='youtube'){draft.name='YouTube';draft.domains='youtube.com\ngooglevideo.com\nytimg.com';draft.testURL='https://www.youtube.com/';}else if(preset.value==='hdrezka'){draft.name='HDRezka';draft.domains='';draft.testURL='';}draw();});body=[self.field('Готовый набор сайтов',preset),self.field('Название группы',input('name','Например, видео')),self.field('Сайты этой группы',domains,'По одному домену на строку, без https:// и пути. Поддомены включены.'),node('p','at-footnote',label(draft.preset==='hdrezka' ? 'Будет добавлен общественный список HDRezka. В следующем шаге укажите фактическое зеркало для проверки. Ни одна ссылка не гарантирует работу всех зеркал.' : 'Например, группа «Видео» может содержать несколько сайтов, использующих одинаковый набор профилей.'))];collect=function(){if(!draft.name.trim())throw new Error('Назовите группу');if(!lines(draft.domains).length && draft.preset==='custom')throw new Error('Добавьте хотя бы один домен');};}
            if(step===2){collect=function(){if(draft.policy==='proxy' && draft.source==='none')throw new Error('Для прокси вернитесь к первому шагу и выберите подключение.');};body=[self.field('Маршрут группы',select('policy',[['proxy','Через выбранное подключение'],['direct','Напрямую, через провайдера'],['block','Блокировать доступ']])),node('p','at-footnote',label('Прокси использует профили выбранного подключения. Прямой маршрут показывает сайту IP вашего провайдера. Блокировка запрещает соединения с сайтами группы. Остальные сайты задаются отдельно.'))];}
            if(step===3){var profiles=(self.data.nodes || []).filter(function(n){return draft.source!=='new' && draft.source!=='none' && n.key.indexOf(draft.source)===0;});body=[];if(draft.policy==='proxy'){var selection=select('selection',[['auto','Автоматически выбирать работающий'],['manual','Использовать один профиль']]);selection.addEventListener('change',draw);body.push(self.field('Выбор профиля',selection));if(draft.selection==='manual')body.push(self.field('Профиль для ручного выбора',select('profile',[['','Выберите профиль']].concat(profiles.map(function(n){return [n.key,n.name];})))));else body.push(self.field('Адрес сайта для проверки',input('testURL','https://www.youtube.com/','url')),self.field('Текст на странице',input('marker','Необязательно: YouTube')),self.field('Интервал проверки, секунд',input('interval','60','number')),node('p','at-footnote',label('Atlas выбирает профиль, который получил HTTP 200 от указанного сайта и нашёл заданный текст, если он указан. Проверяется страница, а не воспроизведение видео. Пустой URL оставляет общий тест задержки. Для разных сайтов создавайте разные группы. При отсутствии подходящего профиля группа блокируется; остальные маршруты сохраняются. Проверки выполняются постепенно, с ограничением времени и числа попыток.')));}else body=[node('p','',label('Для прямого маршрута и блокировки профиль и перебор не нужны.'))];collect=function(){if(draft.policy!=='proxy')return;if(draft.selection==='manual'){if(!draft.profile)throw new Error('Выберите профиль. Для новой подписки сначала используйте автоматический режим.');return;}if(draft.testURL && !/^https:\/\//.test(draft.testURL))throw new Error('Укажите окончательный HTTPS адрес сайта');if(!Number.isInteger(Number(draft.interval)) || Number(draft.interval)<30 || Number(draft.interval)>1800)throw new Error('Интервал — целое число от 30 до 1800 секунд');};}
            if(step===4){var fake=node('input','at-wizard-fakeip',[],{type:'checkbox',checked:draft.fakeip}),dhcp=node('input','at-wizard-dhcp',[],{type:'checkbox',checked:draft.dhcp});fake.addEventListener('change',function(){draft.fakeip=fake.checked;});dhcp.addEventListener('change',function(){draft.dhcp=dhcp.checked;});body=[self.field('Остальные сайты',select('mode',[['rules','Напрямую; через прокси только заданные группы'],['global','Через общий прокси, кроме исключений']])),node('label','at-checkbox',[fake,label('Использовать FakeIP для проксируемых доменов')]),node('label','at-checkbox',[dhcp,label('Направлять DNS dnsmasq в Atlas')]),node('p','at-footnote',label('Эти три настройки общие для Atlas, а не только для новой группы. FakeIP помогает доменной маршрутизации. Интеграция DNS работает для устройств, использующих DNS роутера; встроенный DoH браузера требует отдельной проверки. Остальные настройки безопасности сохраняются.'))];}
            if(step===5){var source=enabled.find(function(x){return x.id===draft.source;});body=[node('div','at-wizard-review',[node('h3','',label(draft.name)),node('p','',label('Сайты: '+(lines(draft.domains).join(', ') || 'общественный список '+draft.preset))),node('p','',label('Маршрут: '+({proxy:'прокси',direct:'напрямую',block:'блокировать'}[draft.policy]))),node('p','',label('Подключение: '+(draft.policy!=='proxy' ? 'не требуется' : source ? source.name : draft.sourceName))),node('p','',label('Выбор: '+(draft.policy!=='proxy' ? 'не требуется' : draft.selection==='auto' ? 'автоматический' : 'ручной'))),node('p','',label('Проверка: '+(draft.policy!=='proxy' || draft.selection==='manual' ? 'не требуется' : draft.testURL || 'общий HTTPS тест задержки'))),node('p','',label('Остальные сайты: '+(draft.mode==='rules' ? 'напрямую' : 'общий прокси'))),node('p','at-footnote',label('Новая группа станет первой среди обычных групп. Будет включён порядок «группа вместе со своими списками». Глобальные исключения сохраняют приоритет. Существующие группы, подключения и секреты сохраняются.'))])];}
            var actions=[self.button('Отмена',function(){ui.hideModal();},'ghost',busy)];
            if(step>0)actions.push(self.button('Назад',function(){step--;draw();},'ghost',busy||saved));
            if(step<5)actions.push(self.button('Далее',function(){try{collect();step++;draw();}catch(e){msg.textContent=e.message;}},'primary',busy));
            else {actions.push(self.button('Сохранить без перезапуска',function(){return save(false);},'ghost',busy));actions.push(self.button('Сохранить и применить',function(){return save(true);},'primary',busy));}
            ui.showModal('Настройка по вопросам · '+(step+1)+' из 6',[node('div','at-modal at-wizard',[node('h2','',label(titles[step])),node('div','at-wizard-body',body),msg]),node('div','at-actions at-wizard-actions',actions)]);
        }
        function save(apply){
            if(busy)return Promise.resolve();busy=true;draw();
            var promise=Promise.resolve(draft.source);
            if(!saved && draft.source==='new' && draft.policy==='proxy')promise=result(api.saveSubscription('',draft.sourceName.trim(),draft.sourceURL,true,'',false)).then(function(){return result(api.status());}).then(function(d){self.data=d;var sub=d.subscriptions.find(function(x){return x.name===draft.sourceName.trim();});if(!sub)throw new Error('Новая подписка не найдена');draft.source=sub.id;enabled=d.subscriptions.filter(function(x){return x.enabled;});return result(api.action('refresh',sub.id)).then(function(){return self.wizardWait();}).then(function(){return sub.id;});});
            return promise.then(function(sourceID){
                if(saved)return;
                if(draft.policy==='proxy' && !(self.data.nodes || []).some(function(n){return n.key.indexOf(sourceID)===0;}))throw new Error('В подключении нет пригодных профилей. Подключение сохранено; проверьте его в разделе «Подключения».');var current=self.data.settings, id=self.newGroupId(),group={id:id,name:draft.name.trim(),enabled:true,policy:draft.policy,domains:lines(draft.domains),cidrs:[],source_ips:[],pool:draft.policy==='proxy' ? sourceID : '',auto_interval_seconds:draft.policy==='proxy' ? Number(draft.interval) : null,site_checks:draft.policy==='proxy' && draft.selection==='auto' && draft.testURL ? [{url:draft.testURL.trim(),statuses:[200],contains:draft.marker}] : []};
                if((current.sections || []).some(function(x){return x.name.toLowerCase()===group.name.toLowerCase();}))throw new Error('Группа с таким названием уже существует. Вернитесь и измените название.');
                var lists=(current.remote_lists || []).slice();
                if(draft.preset!=='custom')lists.unshift({id:self.newGroupId(),name:draft.name+' / '+draft.preset,url:'https://github.com/itdoginfo/allow-domains/releases/latest/download/'+draft.preset+'.srs',policy:draft.policy,format:'srs',enabled:true,section:id,domains:[],cidrs:[]});
                var choices=Object.assign({},current.section_choices || {});if(draft.policy==='proxy' && draft.selection==='manual')choices['section_'+id+'_control']=draft.profile;
                var settings=Object.assign({},current,{sections:[group].concat(current.sections || []),remote_lists:lists,section_choices:choices,group_order:true,mode:draft.mode,fakeip:draft.fakeip,dhcp_dns_enabled:draft.dhcp});
                return result(api.saveSettings(settings)).then(function(){saved=true;});
            }).then(function(){if(apply)return result(api.action('apply','')).then(function(){return self.wizardWait();});}).then(function(){ui.hideModal();return self.reload();}).catch(function(e){busy=false;draw();msg.textContent=(saved ? 'Настройки сохранены, но применение не завершилось. Можно повторить применение без добавления второй группы. ' : '')+(e.message || 'Настройки не удалось сохранить');});
        }
        draw();
    },
    newGroupId: function(){var bytes=new Uint8Array(8);crypto.getRandomValues(bytes);return Array.from(bytes).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join('');},

    privacyLayout: function(content) {
        var basic=[],advanced=[];
        Array.from(content.children).forEach(function(child){var text=child.textContent || '';if(text.indexOf('Проверка безопасности с этого устройства')===0 || text.indexOf('Проверка приватности')===0 || text.indexOf('Функциональная самопроверка')===0)basic.push(child);else advanced.push(child);});
        content.replaceChildren.apply(content,basic.concat([atlasElement('details',{'class':'at-advanced'},[atlasElement('summary',{},'Подробный аудит, FakeIP и сетевые инструменты'),node('div','at-content at-advanced-content',advanced)])]));return content;
    },
    securityCard: function() {
        var self=this,stun=node('input','at-security-stun',[],{type:'checkbox',checked:!!self.securityStun}),report=self.clientSecurity || {};
        stun.addEventListener('change',function(){self.securityStun=stun.checked;});
        var names={ipv4:'Выход IPv4',ipv6:'Выход IPv6',webrtc:'WebRTC',dns:'Внешняя утечка DNS'},states={match:'Совпадает',leak:'Утечка подтверждена',direct:'Прямой маршрут',different:'Другой выход',unknown:'Не подтверждено',unchecked:'Не проверено'};
        return node('section','at-card at-padded at-security-card',[node('h3','',label('Проверка безопасности с этого устройства')),node('p','at-footnote',label('Сначала измерьте общий прокси и прямой выход роутера, затем сравните с браузером. Разные группы могут использовать разные выходы. Прямой маршрут в режиме групп не считается автоматическим доказательством утечки.')),
            node('div','at-actions',[self.button('Рекомендации и настройка защиты',function(){self.securityRecommendations();},'ghost',self.busy()),self.button('Блокировка рекламы',function(){self.adblockDialog();},'ghost',self.busy())]),
            node('div','at-security-steps',[self.button('1. Измерить выходы роутера',function(){return self.action('privacy');},'ghost',self.busy() || !self.data.nodes.length),self.button('2. Проверить браузер и сравнить',function(){return self.clientPrivacyTest({compare:true,stun:!!self.securityStun});},'primary',self.busy())]),
            node('label','at-checkbox',[stun,label('Дополнительно проверить WebRTC через внешний STUN')]),node('p','at-footnote',label('По нажатию IP-сервисы api.ipify.org и api6.ipify.org увидят ваш выходной адрес. При включённом STUN запрос получает stun.l.google.com. Камера и микрофон не используются. Адреса браузера передаются вашему роутеру для сравнения, но не записываются в журнал или состояние. Измеренные выходы сохраняются только как отпечатки на время работы Atlas.')),
            node('div','at-privacy-list',(report.checks || []).map(function(c){return node('div','at-security-result',[pill(states[c.state] || c.state,c.state==='leak' ? 'danger' : c.state==='match' ? 'success' : 'neutral'),node('div','',[node('strong','',label(names[c.id] || c.id)),node('p','at-footnote',label(c.message))])]);})),
            node('p','at-footnote',label(report.notice || 'Недоступный тест получает статус «Не подтверждено», а не «Защита работает». IPv6 без измеренного выхода прокси остаётся неопределённым.')),
            node('div','at-actions',[atlasElement('a',{'class':'at-btn ghost',href:'https://www.dnsleaktest.com/',target:'_blank',rel:'noopener noreferrer'},'3. Внешняя проверка DNS'),atlasElement('a',{'class':'at-btn ghost',href:'https://browserleaks.com/webrtc',target:'_blank',rel:'noopener noreferrer'},'Проверка WebRTC другим сервисом'),self.button('Показать признаки браузера',function(){self.browserFingerprintDialog();},'ghost')]),node('p','at-footnote',label('Внешние страницы увидят IP и диагностические запросы. DNS-тест проводится на самом устройстве: аудит роутера не определяет DNS-over-HTTPS браузера. Atlas не обещает неотслеживаемость: вход в аккаунт, cookies и отпечаток браузера могут идентифицировать пользователя при смене IP.'))]);
    },
    browserFingerprintDialog: function() {
        var items=['Языки: '+(navigator.languages || [navigator.language]).join(', '),'Платформа: '+navigator.platform,'Часовой пояс: '+Intl.DateTimeFormat().resolvedOptions().timeZone,'Размер экрана: '+screen.width+' × '+screen.height,'Cookies: '+(navigator.cookieEnabled ? 'разрешены' : 'выключены')];
        ui.showModal('Признаки, доступные сайтам',[node('p','at-footnote',label('Эти сведения считываются локально и не отправляются внешнему сервису. Это примеры признаков отпечатка, а не оценка уникальности вашего браузера.')),node('div','',items.map(function(t){return node('p','',label(t));})),atlasElement('button',{'class':'btn',click:ui.hideModal},'Закрыть')]);
    },

    securityRecommendations: function() {
        var self=this,s=self.data.settings,msg=node('p','at-inline-error');
        var choices=[
            {key:'dhcp_dns_enabled',title:'Направлять DNS устройств через Atlas',hint:'Устройства, использующие DNS роутера, получат его защищённый DNS. Собственный DoH браузера проверяется отдельно.',checked:s.dhcp_dns_enabled!==false},
            {key:'block_known_doh',title:'Блокировать известные обходные DoH-сервисы',hint:'Снижает обход DNS-фильтра. Может нарушить работу браузера с принудительным защищённым DNS. Не блокирует все возможные DoH адреса.',checked:!!s.block_known_doh},
            {key:'kill_switch',title:'Блокировать защищаемый трафик при отказе Atlas',hint:'При сбое туннеля защищаемые устройства могут остаться без интернета. Сначала проверьте прокси; сохраните локальный доступ к роутеру.',checked:!!s.kill_switch}
        ];
        choices.forEach(function(x){x.input=node('input','at-security-fix-'+x.key,[],{type:'checkbox',checked:x.checked});});
        var global=node('input','at-security-fix-global',[],{type:'checkbox',checked:s.mode==='global'});
        var checks=(self.data.privacy || {}).checks || [];
        ui.showModal('Где защита ограничена и что изменить',[node('div','at-modal',[
            node('div','at-privacy-list',checks.filter(function(x){return !x.ok;}).map(function(x){return node('p','at-footnote',label('Проверить: '+x.label));})),
            node('label','at-checkbox',[global,label('Весь внешний трафик через общий прокси')]),node('p','at-footnote',label('В режиме групп другие сайты идут напрямую. Глобальный режим меняет основной маршрут, но сохраняет явные прямые группы и исключения: удалите ненужные исключения в маршрутизации после проверки.')),
            choices.map(function(x){return node('div','',[node('label','at-checkbox',[x.input,label(x.title)]),node('p','at-footnote',label(x.hint))]);}),
            node('p','at-footnote',label('Atlas не может исправить вход в аккаунты, cookies, отпечаток браузера или настройки расширений. FlClash меняет выход этого компьютера: отдельно проверяйте устройство, которое использует только роутер. Сначала сохраните рекомендации, затем проверьте конфигурацию и примените в обзоре.')),
            msg]),node('div','right',[self.button('Сохранить рекомендации',function(){var settings=Object.assign({},s,{mode:global.checked ? 'global' : 'rules'});choices.forEach(function(x){settings[x.key]=x.input.checked;});return result(api.saveSettings(settings)).then(function(){ui.hideModal();return self.reload();}).catch(function(e){msg.textContent=e.message;});},'primary'),self.button('Отмена',function(){ui.hideModal();},'ghost')])]);
    },

    adblockDialog: function() {
        var self=this,s=self.data.settings,msg=node('p','at-inline-error');
        var presets=[{name:'Peter Lowe — лёгкий список',url:'https://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=0',format:'domains'},
            {name:'HaGeZi Light — реклама и трекеры',url:'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt',format:'adguard'}];
        presets.forEach(function(x){x.input=node('input','at-adblock-preset',[],{type:'checkbox',checked:(s.remote_lists || []).some(function(y){return y.url===x.url && y.policy==='dnsblock' && y.enabled!==false;})});});
        var dns=node('select','at-adblock-dns',[atlasElement('option',{value:'keep'},'Сохранить текущий DNS'),atlasElement('option',{value:'adguard'},'AdGuard DNS — фильтрация рекламы'),atlasElement('option',{value:'cloudflare'},'Cloudflare DNS — без рекламного фильтра')]);
        function choose(kind){if(saving)return Promise.resolve();presets.forEach(function(x,index){x.input.checked=(kind==='peter' && index===0) || (kind==='hagezi' && index===1);});dns.value=kind==='adguard' ? 'adguard' : s.dns_filter==='adguard' ? 'cloudflare' : 'keep';return save(true);}
        var services=[
            {key:'adguard',title:'AdGuard DNS — простой старт',description:'Использует защищённый DNS AdGuard с блокировкой рекламы и известных трекеров. Списки вручную добавлять не нужно. DNS-провайдер изменится на AdGuard; он будет обрабатывать запросы доменных имён.',button:'Включить AdGuard DNS'},
            {key:'hagezi',title:'HaGeZi Light — фильтр на роутере',description:'Atlas скачает список рекламных и отслеживающих доменов и заблокирует их на роутере. Список обновляется по расписанию Atlas. Сохраняется ваш текущий DNS; если был выбран AdGuard DNS, он заменится Cloudflare, чтобы не складывать два готовых фильтра.',button:'Включить HaGeZi Light'},
            {key:'peter',title:'Peter Lowe — небольшой список',description:'Atlas скачает небольшой список рекламных и отслеживающих доменов. Подходит для лёгкой фильтрации и требует меньше памяти, чем большой список. Используется текущий DNS; выбранный AdGuard заменится Cloudflare.',button:'Включить Peter Lowe'}
        ];
        var cards=node('div','at-service-grid',services.map(function(service){return node('section','at-service-card',[node('h3','',label(service.title)),node('p','',label(service.description)),self.button(service.button,function(){return choose(service.key);},'primary',self.busy())]);}));
        var custom=atlasElement('details',{'class':'at-advanced'},[atlasElement('summary',{},'Совместить фильтры или только сохранить настройки'),presets.map(function(x){return node('label','at-checkbox',[x.input,label(x.name)]);}),self.field('DNS-провайдер',dns),node('div','at-actions',[self.button('Сохранить без применения',function(){return save(false);},'ghost'),self.button('Сохранить и включить',function(){return save(true);},'primary')])]);
        var saving=false;function save(apply){if(saving)return Promise.resolve();saving=true;msg.textContent='Сохранение настроек…';var lists=(s.remote_lists || []).map(function(x){return Object.assign({},x);});presets.forEach(function(x){var found=lists.find(function(y){return y.url===x.url && y.policy==='dnsblock';});if(found)found.enabled=x.input.checked;else if(x.input.checked)lists.push({name:x.name,url:x.url,format:x.format,policy:'dnsblock',enabled:true,section:''});});var settings=Object.assign({},s,{remote_lists:lists});if(dns.value!=='keep')settings.dns_filter=dns.value;return result(api.saveSettings(settings)).then(function(){if(!apply){ui.hideModal();return self.reload();}return (presets.some(function(x){return x.input.checked;}) ? result(api.action('refresh_lists','')).then(function(){return self.wizardWait();}) : Promise.resolve()).then(function(){return result(api.action('apply',''));}).then(function(){return self.wizardWait();}).then(function(){ui.hideModal();return self.reload();});}).catch(function(e){msg.textContent='Включение не завершилось: '+e.message+'. Настройки сохранены; проверьте сообщение и повторите включение.';}).finally(function(){saving=false;});}
        var selected=s.dns_filter==='adguard' ? 'AdGuard DNS' : presets.filter(function(x){return x.input.checked;}).map(function(x){return x.name;}).join(', ') || 'готовый фильтр не выбран';
        var active=((self.data.privacy || {}).checks || []).some(function(x){return x.id==='adblock' && x.ok;});
        ui.showModal('Выберите блокировку рекламы',[node('div','at-modal',[node('p','at-footnote',label('Сохранено: '+selected+'. В работающей конфигурации '+(active ? 'обнаружен DNS-фильтр.' : 'DNS-фильтр не подтверждён.'))),node('p','at-footnote',label('Нажмите кнопку выбранного сервиса: Atlas сохранит настройку, при необходимости скачает список и применит фильтрацию. Обычно достаточно одного варианта. Применение перезапускает Atlas; возможен короткий перерыв соединений.')),cards,node('p','at-footnote',label('Блокируются домены рекламы и трекеров на устройствах, использующих DNS Atlas. Собственный DoH браузера может обходить фильтр. Баннерные места на странице и реклама YouTube могут остаться: для их удаления нужно браузерное расширение. Ваши дополнительные списки и группы сохраняются.')),custom,msg]),node('div','right',[self.button('Выключить готовые фильтры',function(){return choose('none');},'ghost'),self.button('Закрыть',function(){ui.hideModal();},'ghost')])]);
    },

    sectionDialog: function(section, commit, listContext) {
        var self = this, original = Object.assign({}, section || {});
        original.id=original.id || self.newGroupId();
        function show(config) {
            var name = node('input', 'at-input at-section-name', [], { value: original.name || '', maxlength: 48 });
            var enabled = node('input', '', [], { type: 'checkbox', checked: original.enabled !== false });
            var policy = node('select', 'at-input at-section-policy', ['proxy','direct','exclude','block','interface'].map(function(x) { return atlasElement('option', { value: x, selected: x === (original.policy || 'proxy') }, {proxy:'Прокси',direct:'Напрямую',exclude:'Исключение',block:'Блокировать',interface:'VPN-интерфейс'}[x]); }));
            var pool = node('select', 'at-input at-section-pool', [atlasElement('option', { value: '', selected: !original.pool }, 'Общий пул / JSON outbound')].concat((self.data.subscriptions || []).filter(function(x) { return x.enabled; }).map(function(x) { return atlasElement('option', { value: x.id, selected: original.pool === x.id }, x.name); })));
            var iface = node('input', 'at-input at-section-interface', [], { value: original.interface || '', placeholder: 'wg0' });
            var resolver = node('input', 'at-input at-section-resolver', [], { value: original.resolver || '', placeholder: 'https://dns.example/dns-query' });
            var resolveIp = node('select','at-input at-section-resolve-ip',[atlasElement('option',{value:'inherit',selected:original.resolve_real_ip == null},'Наследовать общую настройку'),atlasElement('option',{value:'on',selected:original.resolve_real_ip === true},'Включить для этой секции'),atlasElement('option',{value:'off',selected:original.resolve_real_ip === false},'Выключить для этой секции')]);
            var autoInterval = node('input','at-input at-section-auto-interval',[],{type:'number',min:30,max:1800,value:original.auto_interval_seconds == null ? '' : original.auto_interval_seconds,placeholder:'Наследовать'});
            var autoTolerance = node('input','at-input at-section-auto-tolerance',[],{type:'number',min:1,max:2000,value:original.auto_tolerance_ms == null ? '' : original.auto_tolerance_ms,placeholder:'Наследовать'});
            var extensions = self.urltestExtensions(original);
            var sites = self.siteCheckFields(original);
            var autoUrl = node('input','at-input at-section-auto-url',[],{value:original.urltest_url || '',placeholder:'Наследовать общий HTTPS URL'});
            var sectionUot = node('select','at-input at-section-uot',[atlasElement('option',{value:'inherit',selected:original.udp_over_tcp == null},'Наследовать общую настройку'),atlasElement('option',{value:'on',selected:original.udp_over_tcp === true},'Включить'),atlasElement('option',{value:'off',selected:original.udp_over_tcp === false},'Выключить')]);
            var sectionUotVersion = node('select','at-input at-section-uot-version',[atlasElement('option',{value:'inherit',selected:original.udp_over_tcp_version == null},'Наследовать общую версию'),atlasElement('option',{value:'1',selected:original.udp_over_tcp_version === 1},'1'),atlasElement('option',{value:'2',selected:original.udp_over_tcp_version === 2},'2')]);
            var fields = {};
            ['domains','cidrs','source_ips','source_interfaces','ports','networks','exclude_domains','exclude_cidrs','exclude_source_ips'].forEach(function(k) { fields[k] = node('textarea', 'at-input at-textarea at-section-' + k, label((original[k] || []).join('\n')), { rows: 3, spellcheck: 'false' }); });
            var json = node('textarea', 'at-input at-textarea at-section-json', label(JSON.stringify(config || [], null, 2)), { rows: 12, spellcheck: 'false', autocomplete: 'off' });
            var listener = original.mixed_proxy || {};
            var mixed = node('input', 'at-section-mixed', [], { type: 'checkbox', checked: !!listener.enabled });
            var bind = node('input', 'at-input at-section-listen', [], { value: listener.listen || '127.0.0.1', placeholder: '192.168.1.1' });
            var port = node('input', 'at-input at-section-port', [], { type: 'number', min: 1024, max: 65535, value: listener.port || 2081 });
            var username = node('input', 'at-input at-section-username', [], { value: listener.username || '', autocomplete: 'off' });
            var password = node('input', 'at-input at-section-password', [], { type: 'password', autocomplete: 'new-password', placeholder: original.id ? 'Пусто — сохранить прежний пароль' : 'Не менее 12 символов' });
            var listRows=(listContext ? listContext.get() : self.data.settings.remote_lists || []).filter(function(x){return x.section===original.id;}).map(function(x){return Object.assign({},x);});
            var listHolder=node('div','at-section-sources');
            function renderSources(){listHolder.replaceChildren.apply(listHolder,listRows.map(function(item,index){
                var title=node('input','at-input',[],{value:item.name || '',placeholder:'Название списка'});
                var url=node('input','at-input',[],{value:item.url || '',placeholder:item.format==='cidrs' ? 'https://example.org/ip.txt' : 'https://example.org/domains.txt'});
                var format=node('select','at-input',['auto','domains','cidrs','srs','json','hosts','adguard'].map(function(f){return atlasElement('option',{value:f,selected:f===(item.format || 'auto')},f);}));
                var on=node('input','',[],{type:'checkbox',checked:item.enabled!==false});
                title.addEventListener('input',function(){item.name=title.value;});url.addEventListener('input',function(){item.url=url.value;});format.addEventListener('change',function(){item.format=format.value;});on.addEventListener('change',function(){item.enabled=on.checked;});
                return node('div','at-source-row',[node('div','at-grid-2',[self.field('Название списка',title),self.field('Адрес списка или file:///путь',url)]),node('div','at-actions',[node('label','at-checkbox',[on,label('Использовать список')]),self.field('Формат файла',format),self.button('Удалить список',function(){listRows.splice(index,1);renderSources();},'danger-link')])]);
            }));}
            function addSource(format,url,name){listRows.push({id:self.newGroupId(),name:name || 'Новый список',url:url || '',format:format,enabled:true,policy:policy.value==='interface' ? 'proxy' : policy.value,section:original.id});renderSources();}
            var catalogue=node('select','at-input',[['youtube','YouTube'],['hdrezka','HDRezka'],['discord','Discord'],['telegram','Telegram'],['google_ai','Google AI'],['meta','Meta'],['twitter','Twitter / X'],['russia_inside','Россия внутри'],['russia_outside','Россия снаружи'],['geoblock','Геоблокировки']].map(function(x){return atlasElement('option',{value:x[0]},x[1]);}));
            renderSources();
            var sourceEditor=node('section','at-section-sources-editor',[node('h3','',label('Списки этой секции')),node('p','at-footnote',label('Все добавленные здесь списки используют подключение этой секции. Ссылка — файл в интернете; file:/// — существующий файл на роутере. Пустой список ничего не добавляет. Сохранённый адрес с /[saved] оставьте без изменений.')),self.field('Готовый список сайтов',catalogue),self.button('Добавить выбранный список',function(){addSource('srs','https://github.com/itdoginfo/allow-domains/releases/latest/download/'+catalogue.value+'.srs',catalogue.options[catalogue.selectedIndex].textContent);},'ghost'),listHolder,node('div','at-actions',[self.button('+ Внешний список доменов',function(){addSource('domains');},'ghost'),self.button('+ Внешний список IP / подсетей',function(){addSource('cidrs');},'ghost'),self.button('+ Локальный файл на роутере',function(){addSource('auto','file:///etc/atlas/');},'ghost')])]);
            var msg = node('p', 'at-inline-error');
            ui.showModal(original.name ? 'Секция «'+original.name+'»' : 'Новая секция', [self.sectionLayout(node('div', 'at-modal', [
                self.field('Название', name), node('label', 'at-checkbox', [enabled, label('Группа включена')]), self.field('Действие', policy), self.field('Подключение для группы', pool), sourceEditor, self.field('Исходящий VPN-интерфейс', iface),
                node('div', 'at-grid-2', [self.field('Домены', fields.domains), self.field('IP назначения / CIDR', fields.cidrs), self.field('IP устройств / CIDR', fields.source_ips), self.field('Входящие интерфейсы', fields.source_interfaces), self.field('Порты: 443,10000-20000', fields.ports), self.field('Транспорт: tcp,udp', fields.networks)]),
                self.field('DNS resolver для доменов', resolver), self.field('Разрешение реального IP',resolveIp),
                node('p','at-footnote',label('Отдельный DNS применяется к доменам секции независимо от портов и TCP/UDP соединений. Устройства и входящие интерфейсы учитываются, когда DNS-запрос сохраняет эти признаки. DNS-запрос не содержит порт будущего соединения.')),
                node('p','at-footnote',label('ID секций для экспертных связей: '+(self.data.settings.sections || []).map(function(x){return x.name+': '+x.id;}).join(' · '))),
                sites.element, extensions.element,
                atlasElement('details',{},[atlasElement('summary',{},'UDP через TCP для этой секции'),self.field('UDP-over-TCP',sectionUot),self.field('Версия',sectionUotVersion),node('p','at-footnote',label('Для SOCKS и Shadowsocks обычного пула. Сервер должен поддерживать выбранную версию. Секция получает отдельные копии выходов; соседние секции сохраняют свои настройки. В экспертном JSON параметр задаётся в самом outbound.'))]),
                atlasElement('details',{},[atlasElement('summary',{},'Автопроверка серверов этой секции'),self.field('Интервал, секунд',autoInterval),self.field('Допустимая разница задержки, мс',autoTolerance),self.field('HTTPS URL проверки',autoUrl),node('p','at-footnote',label('Пустые поля наследуют общие значения. Для обычного прокси-пула заполненные поля создают независимый selector и URLTest. В экспертном JSON параметры URLTest задаются самим JSON.'))]),
                atlasElement('details',{},[atlasElement('summary',{},'Исключения только из этой секции'),node('div','at-grid-2',[self.field('Исключить домены',fields.exclude_domains),self.field('Исключить IP назначения / CIDR',fields.exclude_cidrs),self.field('Исключить устройства / CIDR',fields.exclude_source_ips)]),node('p','at-footnote',label('Исключённый трафик проверяется следующими правилами. Это не глобальный прямой маршрут. IP назначения проверяется по известному движку адресу; для доменов с FakeIP используйте доменные исключения.'))]),
                atlasElement('details', {}, [atlasElement('summary', {}, 'JSON outbound — расширенная конфигурация'), self.field('Объект, список или {"outbounds": […]}', json), node('p', 'at-footnote', label('Первый outbound — выход секции. Можно указать selector/urltest и связанные узлы с уникальными tag. Для связи с другой экспертной секцией используйте section_<ID секции>_<tag узла>. Несуществующие или выключенные выходы и циклы отвергаются при проверке конфигурации. Параметры протоколов проверяет установленный sing-box. Фильтры подписочного автовыбора к этому JSON не применяются. [] возвращает подписочный пул. Этот JSON может содержать пароли; доступен только администратору.'))]),
                node('label', 'at-checkbox', [mixed, label('Отдельный HTTP/SOCKS-прокси этой секции')]), node('div', 'at-grid-2', [self.field('LAN или loopback IP', bind), self.field('Порт', port), self.field('Имя пользователя', username), self.field('Пароль', password)]),
                node('p', 'at-footnote', label('Весь трафик этого HTTP/SOCKS-прокси использует выход секции. Порт должен быть уникальным. Изменения пока остаются в форме; затем сохраните правила и примените их.')), msg
            ])), node('div', 'right', [atlasElement('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Добавить в форму', function() {
                try {
                    var value = JSON.parse(json.value || '[]');
                    if (value && !Array.isArray(value) && value.outbounds && Object.keys(value).length === 1) value = value.outbounds;
                    if (!Array.isArray(value)) value = [value];
                    var updated = Object.assign({}, original, { id:original.id || self.newGroupId(), name: name.value.trim(), enabled: enabled.checked, policy: policy.value, pool: pool.value, interface: iface.value.trim(), resolver: resolver.value.trim(), outbound_config: value, mixed_proxy: {enabled:mixed.checked,listen:bind.value.trim(),port:Number(port.value),username:username.value.trim(),password:password.value || listener.password || ''} });
                    updated.resolve_real_ip=resolveIp.value==='inherit' ? null : resolveIp.value==='on';
                    updated.udp_over_tcp=sectionUot.value==='inherit' ? null : sectionUot.value==='on';
                    updated.udp_over_tcp_version=sectionUotVersion.value==='inherit' ? null : Number(sectionUotVersion.value);
                    updated.auto_interval_seconds=autoInterval.value.trim() ? Number(autoInterval.value) : null;
                    updated.auto_tolerance_ms=autoTolerance.value.trim() ? Number(autoTolerance.value) : null;
                    updated.urltest_url=autoUrl.value.trim();
                    updated.site_checks=policy.value==='proxy' ? sites.values() : [];
                    Object.assign(updated,extensions.values());
                    delete updated.outbound_config_set;
                    Object.keys(fields).forEach(function(k) { updated[k] = lines(fields[k].value); });
                    if (!updated.name) throw new Error('Введите название секции');
                    if(listRows.some(function(x){return !x.name.trim() || !x.url.trim();}))throw new Error('Заполните название и адрес каждого списка либо удалите пустую строку');
                    listRows.forEach(function(x){x.policy=updated.policy==='interface' ? 'proxy' : updated.policy;});
                    commit(updated); if(listContext)listContext.set(updated.id,listRows); ui.hideModal();
                } catch (e) { msg.textContent = e.message || 'Проверьте JSON'; }
            }, 'primary')])]);
        }
        if (original.outbound_config_set && !original.outbound_config) return result(api.sectionDetails(original.id)).then(function(r) { show(r.outbound_config); });
        show(original.outbound_config || []);
        return Promise.resolve();
    },

    routingPage: function() {
        var self = this, d = self.data, s = d.settings;
        var mode = node('select', 'at-input', [atlasElement('option', { value: 'rules', selected: s.mode === 'rules' }, 'По правилам — остальное напрямую'), atlasElement('option', { value: 'global', selected: s.mode === 'global' }, 'Весь трафик — кроме исключений')]);
        var inputs = {};
        ['domains', 'cidrs', 'bypass_domains', 'bypass_cidrs'].forEach(function(k) { inputs[k] = node('textarea', 'at-input at-textarea at-route-' + k, label(s[k].join('\n')), { rows: 6, spellcheck: 'false', placeholder: k.indexOf('domains') >= 0 ? 'example.org\nexample.net' : '203.0.113.0/24\n2001:db8::/32' }); });
        ['routed_source_ips', 'routing_excluded_ips'].forEach(function(k) { inputs[k] = node('textarea', 'at-input at-textarea at-route-' + k, label((s[k] || []).join('\n')), { rows: 4, spellcheck: 'false', placeholder: '192.168.1.25/32\n2001:db8::25/128' }); });
        var blocked = node('textarea', 'at-input at-textarea', label((s.blocked_domains || []).join('\n')), { rows: 6, spellcheck: 'false', placeholder: 'ads.example\ntracker.example' });
        var sections = node('textarea', 'at-input at-textarea', label((s.sections || []).map(function(x) { return [x.name, x.policy, x.domains.join(','), x.cidrs.join(','), x.source_ips.join(','), x.pool || '', x.interface || '', x.resolver || '', (x.source_interfaces || []).join(','), (x.ports || []).join(','), (x.networks || []).join(',')].join(' | '); }).join('\n')), { rows: 7, spellcheck: 'false', placeholder: 'Работа | proxy | corp.example | | 192.168.1.25/32 | <ID подписки или пусто> | | | br-lan\nVPN intranet | interface | intranet.example | | | | wg0 | https://dns.example/dns-query |\nИсключить | exclude | local.example | | | | | |' });

        var sectionDraft = JSON.parse(JSON.stringify(s.sections || []));
        var sectionListOverrides={};
        var sectionSources={get:function(){var items=(s.remote_lists || []).filter(function(x){return !Object.prototype.hasOwnProperty.call(sectionListOverrides,x.section);});Object.keys(sectionListOverrides).forEach(function(id){items=items.concat(sectionListOverrides[id]);});return items;},set:function(id,items){sectionListOverrides[id]=items;syncSections();}};
        var sectionList = node('div', 'at-section-list');
        var serializedSections = '';
        function syncSections() {
            sections.value = sectionDraft.map(function(x) { return [x.name,x.policy,(x.domains || []).join(','),(x.cidrs || []).join(','),(x.source_ips || []).join(','),x.pool || '',x.interface || '',x.resolver || '',(x.source_interfaces || []).join(','),(x.ports || []).join(','),(x.networks || []).join(',')].join(' | '); }).join('\n');
            serializedSections = sections.value;
            sectionList.replaceChildren.apply(sectionList, sectionDraft.map(function(x, index) {
                function move(delta) { var other = index + delta; if (other < 0 || other >= sectionDraft.length) return; var saved=sectionDraft[index];sectionDraft[index]=sectionDraft[other];sectionDraft[other]=saved;syncSections(); }
                return node('article', 'at-card at-padded', [node('strong', '', label(x.name)), node('p', 'at-footnote', label((x.enabled === false ? 'Выключена · ' : '') + ({proxy:'Прокси',direct:'Напрямую',exclude:'Исключение',block:'Блокировать',interface:'VPN'}[x.policy] || x.policy) + (x.outbound_config_set || (x.outbound_config || []).length ? ' · JSON outbound' : '') + (x.mixed_proxy && x.mixed_proxy.enabled ? ' · HTTP/SOCKS ' + x.mixed_proxy.listen + ':' + x.mixed_proxy.port : ''))), node('p','at-footnote',label((x.domains || []).slice(0,4).join(', ')+(x.domains && x.domains.length>4 ? ' и ещё '+(x.domains.length-4) : '')+' · списков: '+sectionSources.get().filter(function(l){return l.section===x.id;}).length+' · '+(x.site_checks && x.site_checks.length ? 'Автовыбор по доступности '+x.site_checks.length+' сайтов' : x.policy==='proxy' ? 'Общая проверка профилей' : 'Профиль не требуется'))),node('div','at-actions',[
                    self.button('Настроить секцию', function() { return self.sectionDialog(x, function(value) { if(sectionDraft.some(function(y,i){return i!==index&&y.name.toLowerCase()===value.name.toLowerCase();})) throw new Error('Название секции уже используется');sectionDraft[index]=value;syncSections(); },sectionSources); }, '', self.busy()),
                    self.button('Копировать сохранённую',function(){self.cloneSectionDialog(x);},'ghost',self.busy()||!x.id),
                    self.button('↑',function(){move(-1);},'ghost',index===0||self.busy()),self.button('↓',function(){move(1);},'ghost',index===sectionDraft.length-1||self.busy()),
                    self.button('Удалить из формы',function(){sectionDraft.splice(index,1);syncSections();ui.addNotification(null,node('p','',label('Группа удалена из формы. При сохранении связанные списки будут выключены; их источники и кеш сохраняются.')),'info');},'danger-link',self.busy())
                ])]);
            }));
        }
        syncSections();
        var addSection = self.button('+ Группа', function() { return self.sectionDialog(null, function(value) { if(sectionDraft.some(function(x){return x.name.toLowerCase()===value.name.toLowerCase();})) throw new Error('Название секции уже используется');sectionDraft.push(value);syncSections(); },sectionSources); }, 'primary', self.busy());

        function saveRules(apply){ var parsedSections = sections.value === serializedSections ? JSON.parse(JSON.stringify(sectionDraft)) : sections.value.split(/\r?\n/).map(function(x) { return x.trim(); }).filter(Boolean).map(function(line, i) { var parts = line.split('|').map(function(x) { return x.trim(); }); if (parts.length < 8 || parts.length > 11) throw new Error('Секция в строке ' + (i + 1) + ': нужно от 8 до 11 полей, разделённых символом |'); return Object.assign({}, sectionDraft.filter(function(x) { return x.name === parts[0]; })[0] || {}, { name: parts[0], policy: parts[1], domains: parts[2] ? parts[2].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], cidrs: parts[3] ? parts[3].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], source_ips: parts[4] ? parts[4].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], pool: parts[5], interface: parts[6], resolver: parts[7], source_interfaces: parts[8] ? parts[8].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], ports: parts[9] ? parts[9].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], networks: parts[10] ? parts[10].split(',').map(function(x) { return x.trim().toLowerCase(); }).filter(Boolean) : [] }); }); var parsedLists = remoteLists.value.split(/\r?\n/).map(function(x) { return x.trim(); }).filter(Boolean).map(function(line, i) { var parts = line.split('|').map(function(x) { return x.trim(); }); if (parts.length !== 6 && parts.length !== 7) throw new Error('Список в строке ' + (i + 1) + ': нужно 6 или 7 полей, разделённых символом |'); return { name: parts[0], url: parts[1], policy: parts[2], format: parts[3], enabled: parts[4] === 'on', id: parts[5] || undefined, interface: parts[6] || '', section: listSectionChoices[parts[5] || String(i)] ? listSectionChoices[parts[5] || String(i)].value : '', allow_private: !!(listPermissions[parts[5] || String(i)] && listPermissions[parts[5] || String(i)].privateAccess.checked), allow_symlinks: !!(listPermissions[parts[5] || String(i)] && listPermissions[parts[5] || String(i)].symlinks.checked) }; }); parsedLists=parsedLists.filter(function(item){return !Object.prototype.hasOwnProperty.call(sectionListOverrides,item.section);});Object.keys(sectionListOverrides).forEach(function(id){parsedLists=parsedLists.concat(sectionListOverrides[id]);});parsedLists.forEach(function(item){if(item.section && !parsedSections.some(function(g){return g.id===item.section;})){item.section='';item.enabled=false;}});var settings = Object.assign({}, s, { group_order:groupOrder.checked, mode: mode.value, blocked_domains: lines(blocked.value), remote_lists: parsedLists, list_max_bytes:Math.round(Number(listMaxBytes.value)*1048576), fetch_lists_via_proxy: fetchListsViaProxy.checked, fetch_lists_subscription: fetchListsSection.value ? '' : fetchListsSubscription.value, fetch_lists_section: fetchListsSection.value, disable_quic: disableQuic.checked, exclude_ntp: excludeNtp.checked, block_known_doh: blockDoh.checked, sections: parsedSections }); Object.keys(inputs).forEach(function(k) { settings[k] = lines(inputs[k].value); }); return result(api.saveSettings(settings)).then(function() { if(apply){if(Object.keys(sectionListOverrides).length)return result(api.action('refresh_lists','')).then(function(){return self.wizardWait();}).then(function(){return self.action('apply');});return self.action('apply');}ui.addNotification(null, node('p', '', label('Правила сохранены. Нажмите «Сохранить и применить», когда готовы.')), 'info'); return self.reload(); }); }
        var groupOrder=node('input','at-group-order',[],{type:'checkbox',checked:!!s.group_order});
        var disableQuic = node('input', '', [], { type: 'checkbox', checked: !!s.disable_quic });
        var excludeNtp = node('input', '', [], { type: 'checkbox', checked: !!s.exclude_ntp });
        var blockDoh = node('input', '', [], { type: 'checkbox', checked: !!s.block_known_doh });
        var fetchListsViaProxy = node('input', 'at-fetch-lists-proxy', [], { type: 'checkbox', checked: !!s.fetch_lists_via_proxy });
        var fetchListsSubscription = node('select', 'at-input at-fetch-lists-subscription', [atlasElement('option', { value: '', selected: !s.fetch_lists_subscription }, 'Общий авто-пул')].concat((d.subscriptions || []).filter(function(x) { return x.enabled; }).map(function(x) { return atlasElement('option', { value: x.id, selected: s.fetch_lists_subscription === x.id }, x.name + ' · отдельный авто-пул'); })));
        var fetchListsSection = node('select','at-input at-fetch-section',[atlasElement('option',{value:'',selected:!s.fetch_lists_section},'Не использовать отдельную секцию')].concat((s.sections || []).filter(function(x) {return x.enabled !== false && ['proxy','interface','direct'].indexOf(x.policy)>=0;}).map(function(x) {return atlasElement('option',{value:x.id,selected:s.fetch_lists_section===x.id},x.name);} )));
        var listSectionChoices = {};
        var listPermissions = {};
        function groupLists(group){
            var candidates=(s.remote_lists || []).filter(function(item){return item.section===group.id || (!item.section && (item.policy==='proxy' && ['proxy','interface','direct'].indexOf(group.policy)>=0 || item.policy===group.policy && ['direct','block'].indexOf(group.policy)>=0));});
            var checks=candidates.map(function(item){var control=node('input','',[],{type:'checkbox',checked:item.section===group.id});return {item:item,control:control,element:node('label','at-checkbox',[control,label(item.name)])};});
            ui.showModal('Списки группы «'+group.name+'»',[node('p','',label('Отметьте подходящие списки. Их сайты будут проверяться вместе с этой группой. Списки другой группы здесь не переназначаются.')),node('div','',checks.map(function(x){return x.element;})),node('p','at-footnote',label(candidates.length ? 'Изменения попадут в текущую форму. После закрытия сохраните правила и примените их.' : 'Подходящих списков пока нет. Готовый набор можно добавить через мастер; собственный источник — в дополнительных настройках.')),self.button('Добавить в форму',function(){checks.forEach(function(x){listSectionChoices[x.item.id].value=x.control.checked ? group.id : '';});ui.hideModal();},'primary'),self.button('Отмена',function(){ui.hideModal();},'ghost')]);
        }

        var listAssignments = node('div','', (s.remote_lists || []).map(function(item,index) {
            var select = node('select','at-input at-list-section',[atlasElement('option',{value:'',selected:!item.section},'Маршрут из списка')].concat((s.sections || []).filter(function(x) {return x.enabled !== false && (item.policy==='proxy' && ['proxy','interface','direct'].indexOf(x.policy)>=0 || item.policy===x.policy && ['direct','block'].indexOf(x.policy)>=0);}).map(function(x) {return atlasElement('option',{value:x.id,selected:item.section===x.id},x.name);} )));
            listSectionChoices[item.id || String(index)] = select;
            var privateAccess = node('input','at-list-private',[],{type:'checkbox',checked:!!item.allow_private});
            var symlinks = node('input','at-list-symlinks',[],{type:'checkbox',checked:!!item.allow_symlinks});
            listPermissions[item.id || String(index)] = {privateAccess:privateAccess,symlinks:symlinks};
            return node('div','at-card at-padded',[
                self.field('Выход списка «' + item.name + '»',select,'Список использует выход выбранной группы. Для прямого маршрута и блокировки политики списка и группы должны совпадать.'),
                node('label','at-checkbox',[privateAccess,label('Доступ к частным адресам для этого списка')]),
                node('label','at-checkbox',[symlinks,label('Разрешить символьные ссылки для этого списка')])
            ]);
        }));
        var communityLists = [
            ['russia_inside','Россия внутри'],['russia_outside','Россия снаружи'],['ukraine_inside','Украина внутри'],['geoblock','Геоблокировки'],
            ['block','Блок-лист'],['porn','Порнография'],['news','Новости'],['anime','Аниме'],['youtube','YouTube'],['hdrezka','HDRezka'],
            ['tiktok','TikTok'],['google_ai','Google AI'],['google_play','Google Play'],['hodca','HODCA'],['discord','Discord'],['meta','Meta'],
            ['twitter','Twitter / X'],['cloudflare','Cloudflare'],['cloudfront','CloudFront'],['digitalocean','DigitalOcean'],['hetzner','Hetzner'],
            ['ovh','OVH'],['telegram','Telegram'],['roblox','Roblox']
        ];
        var communitySelect = node('select', 'at-input at-community-catalog', communityLists.map(function(x) { return atlasElement('option', { value: x[0] }, x[1] + ' · ' + x[0]); }));
        var communityPolicy = node('select', 'at-input at-community-policy', [
            atlasElement('option', { value: 'proxy', selected: true }, 'Через общий прокси'), atlasElement('option', { value: 'direct' }, 'Напрямую'),
            atlasElement('option', { value: 'block' }, 'Блокировать'), atlasElement('option', { value: 'exclude' }, 'Исключить из прокси'), atlasElement('option', { value: 'interface' }, 'Через VPN интерфейс')
        ]);
        var communityIface = node('input', 'at-input at-community-interface', [], { placeholder: 'wg0 — только для VPN интерфейса' });
        var listMaxBytes = node('input','at-list-max-bytes',[],{type:'number',min:0,max:256,step:1,value:String((s.list_max_bytes == null ? 4194304 : s.list_max_bytes)/1048576)});
        var remoteLists = node('textarea', 'at-input at-textarea', label((s.remote_lists || []).map(function(x) { return [x.name, x.url, x.policy, x.format, x.enabled ? 'on' : 'off', x.id, x.interface || ''].join(' | '); }).join('\n')), { rows: 6, spellcheck: 'false', placeholder: 'EasyList | https://example.org/domains.txt | dnsblock | auto | on | |\nProxy rules | https://example.org/rules.json | proxy | json | on | |\nPrivate routes | https://example.org/routes.txt | proxy | cidrs | on | |' });
        var localTarget = node('select', 'at-input at-local-target', [atlasElement('option', { value: 'proxy' }, 'Через туннель'), atlasElement('option', { value: 'direct' }, 'Напрямую'), atlasElement('option', { value: 'block' }, 'Блокировать')]);
        var localFile = node('input', 'at-input at-local-file', [], { type: 'file', accept: '.txt,.lst,.list,.json,text/plain,application/json', change: function(event) {
            var file = event.target.files && event.target.files[0];
            if (!file) return;
            if (file.size > 4*1024*1024) { error(new Error('Файл должен быть меньше 4 МиБ')); event.target.value = ''; return; }
            var reader = new FileReader();
            reader.onerror = function() { error(new Error('Не удалось прочитать локальный файл')); };
            reader.onload = function() {
                var bytes = new Uint8Array(reader.result), binary = '';
                for (var offset = 0; offset < bytes.length; offset += 8192)
                    binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + 8192));
                result(api.importRules(btoa(binary), localTarget.value)).then(function(r) {
                    ui.addNotification(null, node('p', '', label(r.rules != null ? 'Импортирован JSON ruleset: ' + r.rules + ' правил верхнего уровня.' : 'Импортировано новых правил: ' + r.domains + ' доменов и ' + r.cidrs + ' IP-сетей.')), 'info');
                    return self.reload();
                }).catch(error).finally(function() { event.target.value = ''; });
            };
            reader.readAsArrayBuffer(file);
        } });
        function addCommunityList() {
            var item = communityLists.filter(function(x) { return x[0] === communitySelect.value; })[0];
            if (!item) throw new Error('Выберите community list');
            var routePolicy = communityPolicy.value;
            var iface = routePolicy === 'interface' ? communityIface.value.trim() : '';
            if (routePolicy === 'interface' && !iface) throw new Error('Для VPN интерфейса укажите его имя, например wg0');
            var url = 'https://github.com/itdoginfo/allow-domains/releases/latest/download/' + item[0] + '.srs';
            if (remoteLists.value.split(/\r?\n/).map(function(x) { return x.trim(); }).filter(Boolean).some(function(line) { return line.split('|')[1] && line.split('|')[1].trim() === url; }))
                throw new Error('Этот community list уже добавлен');

            var route = item[0] === 'block' && routePolicy === 'proxy' ? 'block' : routePolicy;
            var line = [item[1], url, route, 'srs', 'on', '', iface].join(' | ');
            remoteLists.value = remoteLists.value.trim() ? remoteLists.value.trim() + '\n' + line : line;
        }
        var listStatus = node('div', 'at-privacy-list', (s.remote_lists || []).map(function(x) {
            var count = Number(x.count || 0);
            return node('div', 'at-privacy-row', [pill(x.error ? 'ОШИБКА' : x.updated ? 'ОБНОВЛЁН' : 'ОЖИДАЕТ', x.error ? 'danger' : x.updated ? 'success' : 'neutral'), node('span', '', label(x.name + ' · ' + (x.format === 'srs' ? 'SRS binary' : count + ' правил') + ' · ' + (x.error || (x.updated ? date(x.updated) : 'не загружен'))))]);
        }));
        return self.routingLayout(node('div', 'at-content', [self.sectionHead('Куда направлять трафик', 'Исключения имеют приоритет. Локальная сеть всегда доступна напрямую.'),
            self.plannerCard(),
            node('section','at-card at-padded',[node('h3','',label('Журнал службы')),node('p','at-footnote',label('Последние 200 строк Atlas из системного журнала. Доступны только администратору; могут содержать адреса и сведения о подключениях.')),self.button('Показать журнал',function(){return result(api.serviceLogs()).then(function(r){ui.showModal('Журнал Atlas',[node('pre','',label(r.content||'Записей нет')),node('p','at-footnote',label(r.truncated?'Показана последняя часть журнала.':'')),atlasElement('button',{'class':'btn',click:ui.hideModal},'Закрыть')]);});},'ghost',self.busy())]),
            node('section', 'at-card at-padded', [self.field('Режим маршрутизации', mode),node('label','at-checkbox',[groupOrder,label('Проверять группы по порядку вместе с их списками')])]),
            node('div', 'at-grid-2', [node('section', 'at-card at-padded', [pill('ЧЕРЕЗ ТУННЕЛЬ', 'purple'), self.field('Домены', inputs.domains, 'По одному на строку. Поддомены включены.'), self.field('IP сети', inputs.cidrs, 'IPv4 и IPv6 в формате CIDR.')]), node('section', 'at-card at-padded', [pill('НАПРЯМУЮ', 'neutral'), self.field('Домены-исключения', inputs.bypass_domains), self.field('IP сети-исключения', inputs.bypass_cidrs)])]),
            node('div', 'at-grid-2', [node('section', 'at-card at-padded', [pill('УСТРОЙСТВА ЧЕРЕЗ ТУННЕЛЬ', 'purple'), self.field('IP устройств / сети', inputs.routed_source_ips, 'Укажите LAN IP устройства или подсеть в CIDR. Локальные адреса назначения остаются напрямую.')]), node('section', 'at-card at-padded', [pill('УСТРОЙСТВА В ОБХОД', 'neutral'), self.field('IP устройств / сети', inputs.routing_excluded_ips, 'Эти устройства используют прямое подключение даже в глобальном режиме.')])]),
            node('section', 'at-card at-padded', [node('h3', '', label('Секции: подключение, сайты и списки')), node('p', 'at-footnote', label('Создавайте правила по сайтам, устройствам, сетям, портам и транспорту. Выбирайте прокси, VPN, прямой маршрут или блокировку. Секции обрабатываются сверху вниз; исключения имеют приоритет.')), sectionList, addSection, atlasElement('details', {}, [atlasElement('summary', {}, 'Текстовый формат секций'), node('p','at-footnote',label('Поля через |: имя | действие | домены | CIDR | источник | пул | интерфейс | DNS | входящие интерфейсы | порты | tcp/udp. Для секций с портами/транспортом задавайте FakeIP отдельной доменной секцией. JSON outbound и настройки прокси сохраняются при совпадении имени.')), self.field('Секция на строку', sections)])]),
            node('section', 'at-card at-padded', [node('h3', '', label('Блокировка доменов')), node('p', '', label('DNS-блокировка по доменам. Укажите по одному на строку; устройства с собственным DoH могут обходить фильтр.')), self.field('Реклама, трекеры и другие домены', blocked)]),
            node('section', 'at-card at-padded', [node('h3', '', label('Импорт локального списка')), node('p', 'at-footnote', label('Загрузите UTF-8 файл .txt/.lst/.json размером до 4 МиБ. Записи проверяются на роутере; содержимое хранится только в правилах Atlas.')), self.field('Действие для правил', localTarget), self.field('Файл доменов / CIDR', localFile)]),
            node('section', 'at-card at-padded', [node('h3', '', label('Удалённые списки правил')), node('p', 'at-footnote', label('HTTP/HTTPS и локальные file:/// списки. Количество источников и записей не ограничено отдельным программным лимитом; учитывайте память роутера. Поддерживаются домены, hosts, CIDR, AdGuard DNS, sing-box JSON и SRS. SRS проверяется движком до сохранения; при ошибке загрузки остаётся прежняя рабочая версия. Параметры URL поддерживаются и скрыты в интерфейсе. Credentials запрещены. Локальным файлам расширение не требуется. JSON сохраняет все поддерживаемые движком поля и логические условия. Временные ошибки загрузки повторяются до трёх попыток. Для сохранённого адреса оставьте URL с /[saved].')), self.field('Максимальный размер файла, МиБ',listMaxBytes,'По умолчанию 4; 0 — без ограничения. Для больших списков требуется достаточно памяти.'), self.field('Каталог community lists', communitySelect), node('div', 'at-grid-2', [self.field('Маршрут каталога', communityPolicy), self.field('VPN интерфейс (если выбран)', communityIface)]), self.button('Добавить community list', addCommunityList, 'ghost', self.busy()), node('label', 'at-checkbox', [fetchListsViaProxy, label('Загружать и обновлять списки через прокси Atlas; при сбое прямого fallback нет')]), self.field('Подписка для обновления', fetchListsSubscription, 'Общий авто-пул или отдельный авто-пул подписки.'), self.field('Секция для обновления', fetchListsSection, 'Имеет приоритет над подпиской; после изменения примените настройки.'), node('p', 'at-footnote', label('Для этой опции Atlas должен быть запущен и настройки применены. Запросы идут через закрытый loopback HTTP proxy выбранного пула.')), self.field('Один список на строку: имя | HTTP/HTTPS URL или file:///путь | proxy/direct/exclude/interface/block/dnsblock | auto/domains/hosts/cidrs/adguard/json/srs | on/off | ID | интерфейс', remoteLists), listAssignments, listStatus]),
            node('section', 'at-card at-padded', [node('h3', '', label('Транспорт и синхронизация')), node('label', 'at-checkbox', [disableQuic, label('Блокировать QUIC (UDP/443), чтобы приложения переходили на TCP')]), node('label', 'at-checkbox', [excludeNtp, label('Направлять NTP (UDP/123) напрямую')]), node('label', 'at-checkbox', [blockDoh, label('Блокировать известные DoH серверы на устройствах')]), node('p', 'at-footnote', label('Блок QUIC действует на весь маршрутизируемый трафик. DoH-блокировка закрывает только известные домены; она не обнаруживает все пользовательские серверы.'))]),
            node('div', 'at-actions', [self.button('Сохранить и применить',function(){return saveRules(true);},'primary',self.busy()),self.button('Сохранить правила', function(){return saveRules(false);}, 'primary', self.busy())]),
            node('p', 'at-footnote', label('Доменные правила используют DNS и распознавание TLS/HTTP/QUIC. Клиентский DoH и ECH могут скрывать домен: для таких назначений используйте IP правила или режим всего трафика.'))]));
    },

    jsonDownloadDialog: function(title, filename, data, notice) {
        var content = JSON.stringify(data, null, 2);
        var box = node('textarea', 'at-input at-textarea', label(content), { rows: 15, readonly: true, spellcheck: 'false' });
        ui.showModal(title, [node('div','at-modal',[node('p','at-footnote',label(notice)),box]),node('div','right',[
            atlasElement('button', {'class':'btn',click:ui.hideModal}, 'Закрыть'), this.button('Скачать JSON',function(){
                var url=URL.createObjectURL(new Blob([content],{type:'application/json;charset=utf-8'}));
                var link=document.createElement('a');link.href=url;link.download=filename;document.body.appendChild(link);link.click();link.remove();setTimeout(function(){URL.revokeObjectURL(url);},1000);
            },'primary')])]);
    },
    backupExport: function() {
        var self=this;
        return result(api.exportBackup()).then(function(r){self.jsonDownloadDialog('Резервная копия Atlas','atlas-backup.json',r.backup,'Копия содержит ссылки подписок, HTTP-заголовки и пароли. Храните её как файл с учётными данными. Кеш DNS, журналы и история соединений не включены.');});
    },
    diagnosticExport: function() {
        var self=this;
        return result(api.diagnosticReport()).then(function(r){self.jsonDownloadDialog('Диагностический отчёт','atlas-diagnostics.json',r.report,'Версии, состояние службы, число источников и результаты проверок. Пароли, ссылки, адреса устройств и история соединений не включены.');});
    },
    backupRestoreDialog: function() {
        var self=this,content=node('textarea','at-input at-textarea at-backup-json',[],{rows:12,spellcheck:'false'}),msg=node('p','at-inline-error');
        var file=node('input','at-input',[],{type:'file',accept:'.json,application/json',change:function(event){
            var selected=event.target.files&&event.target.files[0];if(!selected)return;
            if(selected.size>16*1024*1024){msg.textContent='Копия ограничена 16 МиБ';return;}
            var reader=new FileReader();reader.onload=function(){content.value=reader.result;};reader.onerror=function(){msg.textContent='Не удалось прочитать файл';};reader.readAsText(selected,'utf-8');
        }});
        ui.showModal('Восстановить настройки Atlas',[node('div','at-modal',[self.field('JSON файл резервной копии',file),self.field('Или вставьте JSON',content),node('p','at-footnote',label('Сначала остановите Atlas в обзоре. Восстановление заменяет настройки и источники после проверки; сервис остаётся остановленным. Предыдущие настройки сохраняются на роутере в backup-before-restore.json. Страна выхода после восстановления проверяется заново.')),msg]),node('div','right',[
            atlasElement('button',{'class':'btn',click:ui.hideModal},'Отмена'),self.button('Восстановить настройки',function(){return result(api.restoreBackup(content.value)).then(function(){ui.hideModal();return self.reload();}).catch(function(e){msg.textContent=e.message;});},'primary',self.data.running||self.busy())
        ])]);
    },

    settingsPage: function() {
        var self = this, d = self.data;
        var interval = node('input', 'at-input', [], { type: 'number', min: 1, max: 168, value: d.settings.interval_hours });
        var maxActive = node('select', 'at-input at-max-active', [128,256,512,1024,0].map(function(n) { return atlasElement('option', { value: String(n), selected: Number(d.settings.max_active_nodes == null ? 512 : d.settings.max_active_nodes) === n }, n ? String(n) + ' профилей' : 'Без лимита активного пула'); }));
        var dnsFilter = node('select', 'at-input', [atlasElement('option', { value: 'cloudflare', selected: d.settings.dns_filter === 'cloudflare' }, 'Cloudflare DoH'), atlasElement('option', { value: 'adguard', selected: d.settings.dns_filter === 'adguard' }, 'AdGuard DoH — реклама и трекеры'), atlasElement('option', { value: 'custom', selected: d.settings.dns_filter === 'custom' }, 'Свой DNS')]);
        var yacdEnabled = node('input','at-yacd-enabled',[],{type:'checkbox',checked:!!d.settings.yacd_enabled});
        var yacdWan = node('input','at-yacd-wan',[],{type:'checkbox',checked:!!d.settings.yacd_wan});
        var yacdListen = node('input','at-input at-yacd-listen',[],{value:d.settings.yacd_listen || '127.0.0.1'});
        var dnsType = node('select', 'at-input', [atlasElement('option', { value: 'https', selected: d.settings.custom_dns_type === 'https' }, 'DoH (HTTPS)'), atlasElement('option', { value: 'tls', selected: d.settings.custom_dns_type === 'tls' }, 'DoT (TLS)'), atlasElement('option', { value: 'udp', selected: d.settings.custom_dns_type === 'udp' }, 'UDP (без шифрования)')]);
        var dnsServer = node('input', 'at-input', [], { value: d.settings.custom_dns_server || '', placeholder: '1.1.1.1 или dns.example.net' });
        var dnsSni = node('input', 'at-input', [], { value: d.settings.custom_dns_sni || '', placeholder: 'dns.example.net' });
        var dnsPath = node('input', 'at-input', [], { value: d.settings.custom_dns_path || '/dns-query', placeholder: '/dns-query' });
        var fakeip = node('input', '', [], { type: 'checkbox', checked: !!d.settings.fakeip });
        var fakeipTtl = node('input', 'at-input', [], { type: 'number', min: 1, max: 86400, value: d.settings.fakeip_ttl_seconds || 60 });
        var resolveRealIp = node('input', '', [], { type: 'checkbox', checked: !!d.settings.resolve_real_ip });
        var killSwitch = node('input', '', [], { type: 'checkbox', checked: !!d.settings.kill_switch });
        var bootstrapDnsType = node('select', 'at-input at-bootstrap-type', [atlasElement('option', { value: 'https', selected: (d.settings.bootstrap_dns_type || 'https') === 'https' }, 'DoH (HTTPS)'), atlasElement('option', { value: 'tls', selected: d.settings.bootstrap_dns_type === 'tls' }, 'DoT (TLS)'), atlasElement('option', {value:'udp',selected:d.settings.bootstrap_dns_type === 'udp'},'UDP (без шифрования)')]);
        var bootstrapDnsServer = node('input', 'at-input', [], { value: d.settings.bootstrap_dns_server || '1.1.1.1', placeholder: '1.1.1.1' });
        var bootstrapDnsSni = node('input', 'at-input', [], { value: d.settings.bootstrap_dns_sni || 'cloudflare-dns.com', placeholder: 'cloudflare-dns.com' });
        var bootstrapDnsPath = node('input', 'at-input', [], { value: d.settings.bootstrap_dns_path || '/dns-query', placeholder: '/dns-query' });
        var udpOverTcp = node('input', '', [], { type: 'checkbox', checked: !!d.settings.udp_over_tcp });
        var udpOverTcpVersion = node('select', 'at-input', [atlasElement('option', { value: '2', selected: Number(d.settings.udp_over_tcp_version || 2) === 2 }, 'Версия 2'), atlasElement('option', { value: '1', selected: Number(d.settings.udp_over_tcp_version || 2) === 1 }, 'Версия 1')]);
        var interfaceMonitoring = node('input', '', [], { type: 'checkbox', checked: !!d.settings.interface_monitoring });
        var monitoredInterfaces = node('input', 'at-input', [], { value: (d.settings.monitored_interfaces || []).join(', '), placeholder: 'wan, wan6' });
        var captureInterfaces = node('input', 'at-input', [], { value: (d.settings.capture_interfaces || []).join(', '), placeholder: 'br-lan' });
        var interfaceDelay = node('input','at-input at-interface-delay',[],{type:'number',min:0,max:60000,value:d.settings.interface_reload_delay_ms == null ? 2000 : d.settings.interface_reload_delay_ms});
        var defaultInterface = node('select', 'at-input', [atlasElement('option', { value: '', selected: !d.settings.default_interface }, 'Автоматически (маршрут по умолчанию)')].concat((d.interfaces || []).filter(function(x) { return x !== 'lo' && x !== 'atlas0'; }).map(function(x) { return atlasElement('option', { value: x, selected: d.settings.default_interface === x }, x); })));
        var logLevel = node('select', 'at-input', ['error','warn','info','debug'].map(function(x) { return atlasElement('option', { value: x, selected: (d.settings.log_level || 'warn') === x }, x); }));
        var mixedEnabled = node('input', '', [], { type: 'checkbox', checked: !!d.settings.mixed_proxy_enabled });
        var mixedAddress = node('input', 'at-input', [], { value: d.settings.mixed_proxy_listen || '', placeholder: '192.168.1.1' });
        var mixedPort = node('input', 'at-input', [], { type: 'number', min: 1024, max: 65535, value: d.settings.mixed_proxy_port || 2080 });
        var mixedUser = node('input', 'at-input', [], { value: d.settings.mixed_proxy_username || '', placeholder: 'atlas-client', maxlength: 64 });
        var mixedPass = node('input', 'at-input', [], { type: 'password', autocomplete: 'new-password', placeholder: 'Оставьте пустым, чтобы сохранить пароль' });
        var dhcpDns = node('input', '', [], { type: 'checkbox', checked: !!d.settings.dhcp_dns_enabled });
        var configStorage = node('select', 'at-input at-config-storage', [atlasElement('option', { value: 'flash', selected: (d.settings.config_storage || 'flash') === 'flash' }, 'Flash — сохранять между перезагрузками'), atlasElement('option', { value: 'ram', selected: d.settings.config_storage === 'ram' }, 'RAM — уменьшить запись во flash')]);
        configStorage.appendChild(atlasElement('option',{value:'external',selected:d.settings.config_storage==='external'},'USB / внешний накопитель'));
        var configDir = node('input','at-input at-config-dir',[],{value:d.settings.config_custom_dir || '',placeholder:'/mnt/usb/atlas'});
        var cacheStorage = node('select', 'at-input', [atlasElement('option', { value: 'flash', selected: (d.settings.cache_storage || 'flash') === 'flash' }, 'Flash'), atlasElement('option', { value: 'ram', selected: d.settings.cache_storage === 'ram' }, 'RAM'), atlasElement('option', { value: 'external', selected: d.settings.cache_storage === 'external' }, 'USB/внешнее хранилище')]);
        var cachePath = node('input', 'at-input', [], { value: d.settings.cache_custom_path || '', placeholder: '/mnt/usb/atlas-cache.db' });
        return node('div', 'at-content', [self.sectionHead('Настройки Atlas', 'Обновления и сведения о системе'),
            node('section', 'at-card at-padded', [self.field('Обновлять подписки каждые, часов', interval, 'От 1 до 168. Минутный планировщик запускает обновление только при наступлении срока.'),
                self.field('Активный пул профилей', maxActive, 'Хранится до 4096 профилей суммарно; размер runtime-пула ограничивает память роутера.'),
                self.field('DNS для приложений', dnsFilter, 'Выбранный DNS идет через прокси. UDP вариант шифруется только транспортом прокси.'),
                self.field('Протокол своего DNS', dnsType), self.field('Адрес DNS', dnsServer), self.field('TLS SNI / имя сертификата', dnsSni), self.field('Путь DoH', dnsPath),
                node('hr'), node('h3', '', label('Bootstrap DNS для адресов серверов')), node('p', 'at-footnote', label('Этот resolver напрямую видит домены VPN серверов. Задайте IP, чтобы избежать DNS цикла; поддерживаются DoH и DoT.')),
                self.field('Протокол bootstrap DNS', bootstrapDnsType), self.field('IP DNS сервера', bootstrapDnsServer), self.field('TLS имя сервера', bootstrapDnsSni), self.field('Путь DoH', bootstrapDnsPath),
                node('label', 'at-checkbox', [fakeip, label('Использовать FakeIP для доменов через прокси')]),
                self.field('TTL FakeIP, секунд', fakeipTtl, 'Срок, после которого устройства забывают синтетический адрес. По умолчанию 60 секунд.'),
                node('label', 'at-checkbox', [resolveRealIp, label('Повторно разрешать реальные IP перед маршрутизацией')]),
                node('label', 'at-checkbox', [killSwitch, label('Fail-closed: блокировать LAN → WAN при остановке Atlas')]),
                node('p', 'at-footnote', label('При включении firewall4 блокирует прямую пересылку LAN→WAN, если Atlas/TUN недоступен. Отключение Atlas тогда оставит LAN без интернета до выключения этой опции.')),
                node('hr'), node('h3', '', label('DNS клиентов и dnsmasq')),
                self.field('Входные интерфейсы LAN', captureInterfaces, 'Например br-lan. Пустое значение включает перехват для всех входных сетей.'),
                node('label', 'at-checkbox', [dhcpDns, label('Автоматически направлять DNS dnsmasq в Atlas')]),
                node('p', 'at-footnote', label('При включении сохраняются исходные UCI параметры server/noresolv/cachesize и восстанавливаются при остановке. Проверка приватности показывает текущее состояние DHCP/DNS. Для клиентов со статическим DNS настройте DNS вручную.')),
                node('p', 'at-footnote', label('Маршрутизируемые домены разрешаются через выбранный защищённый DNS. Для прокси с собственным резолвером это помогает не направлять FakeIP обратно в туннель.')),
                node('p', 'at-footnote', label('В режиме «По правилам» FakeIP применяется к доменам из списка «Через туннель». В глобальном режиме — ко всем DNS-запросам. Сам по себе FakeIP не скрывает личность.')),
                node('label', 'at-checkbox', [udpOverTcp, label('UDP over TCP для Shadowsocks и SOCKS')]), self.field('Версия UDP over TCP', udpOverTcpVersion, 'Может помочь при нестабильном UDP; сервер должен поддерживать выбранную версию.'),
                node('hr'), node('h3','',label('Внешняя панель YACD')),
                node('label','at-checkbox',[yacdEnabled,label('Включить YACD')]),
                self.field('Адрес панели на роутере',yacdListen,'127.0.0.1, LAN IP или 0.0.0.0 при включённом WAN-доступе. Порт 19090.'),
                node('label','at-checkbox',[yacdWan,label('Разрешить адрес WAN / все интерфейсы')]),
                node('p','at-footnote',label('Правило firewall автоматически не открывается. Для доступа используется обязательный секретный ключ.')),
                self.button('Адрес и ключ панели',function(){return result(api.dashboardAccess()).then(function(r){var host=r.controller.split(':')[0];if(host==='0.0.0.0')host=location.hostname;ui.showModal('Подключение YACD',[node('p','',label('http://' + host + ':19090/ui')),node('input','at-input',[],{value:r.secret,readonly:true}),node('p','at-footnote',label('Ключ даёт управление прокси. Передавайте его только доверенным устройствам.')),self.button('Закрыть',function(){ui.hideModal();},'ghost')]);});},'ghost',self.busy()),
                node('hr'), node('h3', '', label('LAN HTTP/SOCKS proxy')), node('label', 'at-checkbox', [mixedEnabled, label('Включить listener для устройств LAN')]),
                self.field('Частный LAN IP роутера', mixedAddress, 'Только выбранный RFC1918 / IPv6 ULA адрес; не 0.0.0.0.'), self.field('Порт', mixedPort), self.field('Имя пользователя', mixedUser), self.field('Пароль', mixedPass, 'Минимум 12 символов. Сохранённый пароль обратно в браузер не передаётся.'),
                node('p', 'at-footnote', label('Доступ открыт только на заданном частном IP и защищён паролем. В LuCI укажите http://IP:порт для HTTP CONNECT или socks5://IP:порт для SOCKS.')),
                node('hr'), node('h3', '', label('Мониторинг WAN')), node('label', 'at-checkbox', [interfaceMonitoring, label('Перезапускать sing-box после восстановления выбранной сети')]), self.field('Задержка после подъёма WAN, мс',interfaceDelay,'0–60000; событие обрабатывается без ожидания минутного планировщика.'), self.field('Логические интерфейсы OpenWrt', monitoredInterfaces, 'Например wan, wan6. Событие ifup перезапустит Atlas один раз; ifdown только записывается.'),
                node('hr'), node('h3', '', label('Хранение конфигурации и кеша')), self.field('Внешний каталог конфигурации',configDir,'Абсолютный путь к каталогу. Существующие права каталога сохраняются.'), self.field('Рабочая конфигурация', configStorage, 'RAM уменьшает записи flash, но состояние подписок и настроек всё равно сохраняется в /etc/atlas.'),
                self.field('Кеш DNS/FakeIP', cacheStorage, 'Можно указать собственный абсолютный путь к файлу кеша.'), self.field('Путь кеша', cachePath, 'Используется только при выборе USB/внешнего хранилища; укажите файл .db.'),
                node('hr'), node('h3', '', label('Выход sing-box в сеть')), self.field('Сетевой интерфейс', defaultInterface, 'Пустое значение автоматически использует текущий маршрут. Можно закрепить исходящие соединения за интерфейсом OpenWrt.'), self.field('Уровень журнала', logLevel, 'Режим debug пишет больше сетевых метаданных и занимает больше места; используйте временно для диагностики.'),
                self.button(d.running ? 'Сохранить и применить' : 'Сохранить настройки', function() { var safeLists = (d.settings.remote_lists || []).map(function(x) { return { id: x.id, name: x.name, url: x.url, policy: x.policy, format: x.format, enabled: x.enabled, interface: x.interface || '', section:x.section || '', allow_private:!!x.allow_private, allow_symlinks:!!x.allow_symlinks }; }); return result(api.saveSettings(Object.assign({}, d.settings, { remote_lists: safeLists, capture_interfaces: lines(captureInterfaces.value), yacd_enabled:yacdEnabled.checked, yacd_wan:yacdWan.checked, yacd_listen:yacdListen.value.trim(), interval_hours: Number(interval.value), max_active_nodes: Number(maxActive.value), dns_filter: dnsFilter.value, custom_dns_type: dnsType.value, custom_dns_server: dnsServer.value.trim(), custom_dns_sni: dnsSni.value.trim(), custom_dns_path: dnsPath.value.trim(), bootstrap_dns_type: bootstrapDnsType.value, bootstrap_dns_server: bootstrapDnsServer.value.trim(), bootstrap_dns_sni: bootstrapDnsSni.value.trim(), bootstrap_dns_path: bootstrapDnsPath.value.trim(), udp_over_tcp: udpOverTcp.checked, udp_over_tcp_version: Number(udpOverTcpVersion.value), interface_monitoring: interfaceMonitoring.checked, monitored_interfaces: lines(monitoredInterfaces.value), interface_reload_delay_ms:Number(interfaceDelay.value), default_interface: defaultInterface.value, log_level: logLevel.value, fakeip: fakeip.checked, browser_diagnostics: fakeip.checked && !!d.settings.browser_diagnostics, fakeip_ttl_seconds: Number(fakeipTtl.value), resolve_real_ip: resolveRealIp.checked, kill_switch: killSwitch.checked, dhcp_dns_enabled: dhcpDns.checked, config_storage: configStorage.value, config_custom_dir:configStorage.value === 'external' ? configDir.value.trim() : '', cache_storage: cacheStorage.value, cache_custom_path: cacheStorage.value === 'external' ? cachePath.value.trim() : '', mixed_proxy_enabled: mixedEnabled.checked, mixed_proxy_listen: mixedAddress.value.trim(), mixed_proxy_port: Number(mixedPort.value), mixed_proxy_username: mixedUser.value.trim(), mixed_proxy_password: mixedPass.value }))).then(function() { return d.running ? self.action('apply') : self.reload(); }).then(function() { ui.addNotification(null, node('p', '', label('Настройки сохранены')), 'info'); }); }, 'primary', self.busy())]),
            node('section', 'at-card at-padded', [node('h3', '', label('Резервная копия и диагностика')), node('div','at-actions',[self.button('Экспорт настроек',function(){return self.backupExport();},'',self.busy()),self.button('Восстановить из копии',function(){self.backupRestoreDialog();},'',self.busy()||d.running),self.button('Диагностический отчёт',function(){return self.diagnosticExport();},'',self.busy())]), node('p','at-footnote',label('Для восстановления остановите службу в обзоре. Резервная копия содержит секреты; диагностический отчёт их исключает.'))]),
            node('section', 'at-card at-padded', [node('h3', '', label('Система')), node('dl', 'at-details', [node('dt', '', label('Atlas')), node('dd', '', label(d.version + ' beta')), node('dt', '', label('Движок')), node('dd', '', label(d.engine || 'Не установлен')), node('dt', '', label('Применение')), node('dd', '', label(d.applied.at ? date(d.applied.at) : 'Не применялось')), node('dt', '', label('Watchdog')), node('dd', '', label(d.watchdog && d.watchdog.reason ? d.watchdog.reason + ' · ' + date(d.watchdog.at) : 'Ошибок восстановления нет')), node('dt', '', label('Конфигурация')), node('dd', '', label('sing-box check + ограниченный откат к последней рабочей конфигурации'))])]),
            node('p', 'at-footnote', label('Atlas управляет собственным экземпляром sing-box. Одновременная работа с Podkop, Passwall или OpenClash блокируется. Ссылка подписки не показывается в статусе или журнале Atlas.'))]);
    },
    monitorPage: function() {
        var self = this, m = self.monitor || {}, connections = m.connections || [], rules = m.rules || [], resources = m.resources || {}, cache = resources.cache || {}, system = resources.system || {};
        return node('div', 'at-content', [
            self.sectionHead('Монитор соединений', 'Снимок локального API sing-box. Данные доступны только администраторам LuCI и не отправляются наружу.',
                self.button('Обновить', function() { return self.requestMonitor().then(function(data) { self.monitor = data; self.draw(); }); }, 'small', self.busy())),
            !m.available ? node('div', 'at-notice', label(m.message || 'Загрузка данных монитора…')) : label(''),
            node('div', 'at-stats', [
                self.stat('СОЕДИНЕНИЯ', String(connections.length), m.truncated ? 'Часть потоков и правил скрыта' : 'Активные потоки'),
                self.stat('ОТДАНО', bytes(m.upload_total), 'Счётчик процесса sing-box'),
                self.stat('ПОЛУЧЕНО', bytes(m.download_total), 'Счётчик процесса sing-box'),
                self.stat('ПАМЯТЬ', m.memory && m.memory.inuse ? bytes(m.memory.inuse) : '—', m.memory && m.memory.oslimit ? 'лимит ' + bytes(m.memory.oslimit) : 'sing-box')
            ]),
            node('div', 'at-stats', [
                self.stat('КЭШ', typeof cache.size_bytes === 'number' ? bytes(cache.size_bytes) : '—', 'Размер базы на диске'),
                self.stat('СВОБОДНО', typeof cache.free_bytes === 'number' ? bytes(cache.free_bytes) : '—', 'На разделе кэша'),
                self.stat('ДОСТУПНАЯ RAM', typeof system.available_bytes === 'number' ? bytes(system.available_bytes) : '—', 'Для всей системы')
            ]),
            node('div', '', (resources.warnings || []).map(function(warning) { return node('div', 'at-notice', label(warning)); })),
            node('p', 'at-footnote', label('Снимок обновляется, пока открыт монитор. Большой кэш сам по себе не доказывает утечку; автоматическая очистка не выполняется, чтобы сохранить действующие FakeIP-сопоставления.')),
            node('section', 'at-card at-padded', [node('h3', '', label('Активные соединения')),
                connections.length ? node('div', 'at-table-wrap', [node('table', 'at-table', [
                    node('thead', '', [node('tr', '', ['Назначение','Источник','Протокол','Маршрут','Трафик'].map(function(x) { return node('th', '', label(x)); }))]),
                    node('tbody', '', connections.map(function(c) {
                        return node('tr', '', [
                            node('td', '', [node('strong', '', label(c.host || c.destination || 'неизвестный адрес')), node('small', '', label(c.rule ? c.rule + (c.rule_payload ? ' · ' + c.rule_payload : '') : 'Правило не указано'))]),
                            node('td', '', label(c.source || '—')),
                            node('td', '', label((c.network || '—').toUpperCase())),
                            node('td', '', label((c.chains || []).join(' → ') || 'неизвестно')),
                            node('td', '', label('↑ ' + bytes(c.upload) + ' · ↓ ' + bytes(c.download)))
                        ]);
                    }))
                ])]) : node('p', 'at-footnote', label(m.available ? 'Активных соединений сейчас нет.' : 'Нет данных от движка.'))
            ]),
            node('section', 'at-card at-padded', [node('h3', '', label('Правила, совпавшие с трафиком')),
                rules.length ? node('div', 'at-table-wrap', [node('table', 'at-table', [
                    node('thead', '', [node('tr', '', ['Тип','Условие','Выход'].map(function(x) { return node('th', '', label(x)); }))]),
                    node('tbody', '', rules.map(function(r) { return node('tr', '', [node('td', '', label(r.type)), node('td', '', label(r.payload)), node('td', '', label(r.outbound))]); }))
                ])]) : node('p', 'at-footnote', label('Сработавших правил нет или API недоступен.'))
            ]),
            node('p', 'at-footnote', label('Хосты, источники, правила и счётчики могут раскрывать привычки использования сети. LuCI получает их только при открытой этой вкладке; API sing-box привязан к 127.0.0.1.'))
        ]);
    },
    clientPrivacyTest: function(options) {
        options=options || {};var observations={ipv4:'',ipv6:'',webrtc:[],stun:!!options.stun};
        var self = this;
        self.clientPrivacy = ['Проверка выполняется…'];
        self.draw();
        function publicIP(host, family) {
            var controller = new AbortController(), timer = setTimeout(function() { controller.abort(); }, 8000);
            return fetch('https://' + host + '/?format=json', { signal: controller.signal, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' })
                .then(function(r) { if (!r.ok) throw new Error('HTTP'); return r.json(); })
                .then(function(r) {
                    if (!r || typeof r.ip !== 'string' || r.ip.length > 45 || !/^[0-9a-fA-F:.]+$/.test(r.ip)) throw new Error('IP');
                    observations[family==='IPv4' ? 'ipv4' : 'ipv6']=r.ip;
                    return family + ': ' + r.ip + ' — адрес, видимый с этого браузера';
                }).catch(function() { return family + ': ответ не получен (нет маршрута, блокировка или сервис недоступен)'; })
                .finally(function() { clearTimeout(timer); });
        }
        function rtc() {
            return new Promise(function(resolve) {
                if (typeof RTCPeerConnection === 'undefined') { resolve('WebRTC: API недоступен'); return; }
                var pc, timer, addresses = [], finished = false;
                function done() {
                    if (finished) return;
                    finished = true; clearTimeout(timer); if (pc) pc.close();
                    resolve((options.stun ? 'WebRTC со STUN: ' : 'WebRTC без STUN: ') + (addresses.length ? 'локальные ICE адреса: ' + addresses.join(', ') : 'адреса не получены; это не доказывает отсутствие утечек'));
                }
                try {
                    pc = new RTCPeerConnection({ iceServers: options.stun ? [{urls:'stun:stun.l.google.com:19302'}] : [] });
                    timer = setTimeout(done, 4000);
                    pc.onicecandidate = function(event) {
                        if (!event.candidate) { done(); return; }
                        var address = event.candidate.address;
                        if (!address) { var fields = event.candidate.candidate.split(' '); address = fields[4]; }
                        if (address && /^[a-zA-Z0-9:.\-]{1,253}$/.test(address) && addresses.indexOf(address) < 0 && addresses.length < 16) addresses.push(address);
                    };
                    observations.webrtc=addresses;
                    pc.createDataChannel('atlas-local-check');
                    pc.createOffer().then(function(offer) { return pc.setLocalDescription(offer); }).catch(done);
                } catch (e) { done(); }
            });
        }
        return Promise.all([publicIP('api.ipify.org', 'IPv4'), publicIP('api6.ipify.org', 'IPv6'), rtc()]).then(function(results) {
            self.clientPrivacy = results; self.draw();
            if(options.compare)return result(api.securityCompare(observations)).then(function(r){self.clientSecurity=r;self.draw();}).catch(function(e){self.clientSecurity={checks:[],notice:'Сравнение недоступно: '+e.message};self.draw();});
        });
    },
    browserFakeipTest: function() {
        var self = this;
        function query(host) {
            var controller = new AbortController(), timer = setTimeout(function() { controller.abort(); }, 8000);
            return fetch('https://' + host + '/check', { signal: controller.signal, credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' }).then(function(response) {
                if (!response.ok) throw new Error('HTTP ' + response.status);
                return response.text();
            }).then(function(body) {
                if (body.length > 4096) throw new Error('Ответ слишком большой');
                var data = JSON.parse(body);
                if (typeof data.IP !== 'string' || !/^[0-9a-fA-F:.]{2,45}$/.test(data.IP)) throw new Error('Некорректный IP');
                return data;
            }).finally(function() { clearTimeout(timer); });
        }
        return Promise.all([query('fakeip.podkop.fyi'), query('ip.podkop.fyi')]).then(function(values) {
            if (typeof values[0].fakeip !== 'boolean') throw new Error('Нет результата FakeIP');
            self.browserFakeip = [values[0].fakeip ? 'Браузер использует маршрут FakeIP.' : 'FakeIP не подтверждён: проверьте DNS/DoH клиента.',
                values[0].IP !== values[1].IP ? 'Прямой и прокси выходы различаются.' : 'Выходы совпадают: отдельный выход прокси не подтверждён.'];
        }).catch(function(error) { self.browserFakeip = ['Проверка недоступна: ' + error.message]; }).then(function() { self.draw(); });
    },
    privacyPage: function() {
        var self = this, p = this.data.privacy || {}, checks = p.checks || [], egress = this.data.privacy_egress || {}, test = this.data.selftest || {};
        return self.privacyLayout(node('div', 'at-content', [this.securityCard(),this.sectionHead('Проверка приватности', 'Аудит активной конфигурации Atlas.'),
            node('section','at-card at-padded',[node('h3','',label('Firewall и маршрутизация')),node('p','at-footnote',label('Читает таблицы и правила nftables, маршруты IPv4/IPv6 и правила выбора таблиц. Отчёт содержит сетевые адреса и доступен администратору.')),self.button('Проверить nftables',function(){return result(api.nftDiagnostics()).then(function(r){ui.showModal('Диагностика nftables',[node('div','',r.checks.map(function(c){return node('p','',label((c.ok?'OK · ':'ПРОВЕРИТЬ · ')+c.label));})),node('pre','',label(JSON.stringify(r,null,2))),atlasElement('button',{'class':'btn',click:ui.hideModal},'Закрыть')]);});},'ghost',self.busy())]),
            node('section', 'at-card at-padded', [node('h3', '', label('FakeIP в браузере и цепочка прокси')),
                node('p', 'at-footnote', label('Внешние сервисы fakeip.podkop.fyi и ip.podkop.fyi увидят прямой и прокси IP. Диагностика создаёт исключение прямого маршрута только для первого домена. Результаты остаются в памяти страницы. Проверка не доказывает анонимность.')),
                node('div', 'at-actions', [self.button(self.data.settings.browser_diagnostics ? 'Отключить диагностические маршруты' : 'Включить FakeIP и диагностические маршруты', function() {
                    return result(api.saveSettings(Object.assign({}, self.data.settings, { fakeip: true, browser_diagnostics: !self.data.settings.browser_diagnostics }))).then(function() { return self.action('apply'); });
                }, '', self.busy() || !self.data.nodes.length), self.button('Проверить FakeIP браузера', function() { return self.browserFakeipTest(); }, 'primary', !self.data.running || !self.data.settings.browser_diagnostics)]),
                node('div', 'at-privacy-list', (self.browserFakeip || []).map(function(x) { return node('p', 'at-footnote', label(x)); }))]),
            node('section', 'at-card at-padded', [node('div', 'at-section-head', [node('div', '', [node('h3', '', label('Функциональная самопроверка')), node('p', '', label(test.checked ? 'Последняя проверка: ' + date(test.checked) + (test.ok ? ' · ошибок нет' : ' · есть пункты для проверки') : 'Проверяет конфигурацию, процесс, локальный API, TUN, FakeIP через dnsmasq, DNS и HTTPS через выбранный сервер.'))]), self.button('Запустить самопроверку', function() { return self.action('selftest'); }, 'primary', self.busy() || !this.data.nodes.length)]),
                node('div', 'at-privacy-list', (test.checks || []).map(function(c) { return node('div', 'at-privacy-row', [node('span', 'at-pill ' + (c.ok ? 'success' : 'danger'), label(c.ok ? 'OK' : 'ПРОВЕРИТЬ')), node('span', '', label(c.label))]); })),
                node('p', 'at-footnote', label(test.notice || 'HTTPS проверка подтверждает один прокси с роутера. Она не подменяет проверку с клиентского устройства.'))]),
            node('section', 'at-card at-padded', [node('div', 'at-actions', [pill(checks.filter(function(c) { return c.ok; }).length + ' / ' + checks.length + ' проверок', checks.length && checks.every(function(c) { return c.ok; }) ? 'success' : 'neutral')]),
                node('div', 'at-privacy-list', checks.map(function(c) { return node('div', 'at-privacy-row', [node('span', 'at-pill ' + (c.ok ? 'success' : 'danger'), label(c.ok ? 'OK' : 'ПРОВЕРИТЬ')), node('span', '', label(c.label))]); })),
                node('p', 'at-footnote', label(p.notice || 'Аудит анализирует настройки приложения; это не проверка с внешнего устройства.'))]),
            node('section', 'at-card at-padded', [node('div', 'at-section-head', [node('div', '', [node('h3', '', label('Внешний IP через прокси')), node('p', '', label(egress.status === 'done' ? (egress.same_exit ? 'Напрямую и через выбранный узел виден одинаковый IP.' : 'IP напрямую отличается от IP через выбранный узел.') : egress.status === 'error' ? egress.error : 'Сравнивает IP роутера напрямую и через один выбранный узел.'))]), self.button('Запустить тест', function() { return self.action('privacy'); }, 'primary', self.busy() || !self.data.nodes.length)]),
                node('p', 'at-footnote', label('По нажатию Atlas отправит два HTTPS-запроса к api.ipify.org. Этот внешний сервис увидит IP роутера и IP прокси. Atlas сохраняет только результат сравнения, не сами адреса. Тест одного узла не проверяет DNS с клиентского устройства и не доказывает анонимность.'))]),
            node('section', 'at-card at-padded', [node('div', 'at-section-head', [node('h3', '', label('Проверка с этого браузера')), self.button('Проверить браузер', function() { return self.clientPrivacyTest(); }, 'primary')]),
                node('div', 'at-privacy-list', (self.clientPrivacy || []).map(function(x) { return node('p', 'at-footnote', label(x)); })),
                node('p', 'at-footnote', label('По нажатию браузер отправляет запросы к api.ipify.org и api6.ipify.org; сервис видит ваш выходной IP. WebRTC проверяется локально без STUN. Адреса остаются в памяти страницы и не отправляются роутеру. Сравните их с выходом прокси. Доступность IPv6 сама по себе не означает утечку; эта проверка не измеряет DNS/DoH и WebRTC через STUN.'))]),
            node('section', 'at-card at-padded', [node('h3', '', label('Ограничения проверки')), node('p', 'at-footnote', label('Atlas не видит собственный DoH/VPN клиента и не обещает анонимность. В режиме «По правилам» трафик вне заданных правил идёт напрямую. Для защиты всей сети выберите глобальный режим и дополнительно проверьте соединение с клиентского устройства.'))])]));
    }
});


