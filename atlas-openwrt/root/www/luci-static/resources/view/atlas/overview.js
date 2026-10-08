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
    nftDiagnostics: rpc.declare({object:'atlas',method:'nft_diagnostics',expect:{}})
};

function node(tag, cls, children, attrs) {
    return E(tag, Object.assign({ 'class': cls || '' }, attrs || {}), children == null ? [] : children);
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
            var monitor = self.tab === 'monitor' && !self.readonly ? result(api.monitor()).catch(function(e) {
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
        return node('div', '', [E('link', { rel: 'stylesheet', href: L.resource('atlas/atlas.css') }), this.root]);
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
    navigate: function(tab) {
        this.tab = tab;
        if (tab === 'monitor' && !this.readonly) {
            var self = this;
            result(api.monitor()).then(function(m) { self.monitor = m; if (self.tab === 'monitor') self.draw(); })
                .catch(function(e) { self.monitor = { available: false, message: e.message || 'Монитор недоступен', connections: [], rules: [] }; self.draw(); });
        }
        this.draw();
    },
    draw: function() {
        var self = this, d = self.data;
        var navigation = [ ['overview', '◈', 'Обзор'], ['subscriptions', '▤', 'Подписки'], ['nodes', '◎', 'Серверы'], ['routing', '⇄', 'Маршрутизация'], ['privacy', '◉', 'Приватность'] ];
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
            node('header', 'at-topbar', [node('div', '', [node('span', 'at-crumb', label('Сеть / Atlas')), node('h1', '', label(title))]), pill('sing-box', 'neutral')]),
            self.readonly ? node('div', 'at-notice', label('Режим чтения: изменения доступны администратору.')) : label(''),
            self.offline ? node('div', 'at-notice error', label('Нет связи с роутером. Показаны последние полученные данные.')) : label(''),
            !d.engine ? node('div', 'at-notice error', label('sing-box не найден. Установите движок версии 1.12 или новее.')) : label(''),
            ['queued','running'].indexOf((d.job || {}).status) >= 0 ? node('div', 'at-notice', [node('span', 'at-spinner'), label(d.job.message || 'Выполняется операция…')]) : label(''),
            self[self.tab + 'Page']()
        ]);
        self.root.replaceChildren(sidebar, content);
    },
    sectionDashboard: function() {
        var self = this, panel = node('section', 'at-card at-padded', []);
        function load() { return result(api.sectionDashboard()).then(function(r) {
            panel.replaceChildren(node('h3', '', label('Серверы секций')), self.button('Обновить секции', load, 'ghost', self.busy()));
            (r.sections || []).forEach(function(section) {
                var card = node('div', 'at-padded', [node('h4', '', label(section.name))]);
                section.groups.forEach(function(group) {
                    var selection = node('select', 'at-input', group.members.map(function(m) { return E('option', {value:m.tag, selected:m.tag === group.selected}, m.name + (m.delay ? ' · ' + m.delay + ' мс' : '')); }));
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
        return panel;
    },
    overviewPage: function() {
        var self = this, d = self.data, checks = d.checks || {};
        var measured = d.nodes.filter(function(n) { return checks[n.key] && checks[n.key].ok; });
        var healthy = measured.length;
        var selected = d.runtime && d.runtime.blocked ? (d.runtime.reason === 'no-main-pool' ? d.runtime.message : 'Заблокирован критериями выбора') : d.runtime && d.runtime.available && d.runtime.selected ? d.runtime.name : 'Выбор движка пока неизвестен';
        return node('div', 'at-content', [
            node('section', 'at-hero', [
                node('div', 'at-hero-copy', [pill('ВАША СЕТЬ, ВАШИ ПРАВИЛА', 'eyebrow'), node('h2', '', label('Всё идёт своим путём.')),
                    node('p', '', label('Управляйте подписками и выбирайте, какой трафик отправлять через туннель.')),
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
                self.stat('МАРШРУТИЗАЦИЯ', d.settings.mode === 'rules' ? 'По правилам' : 'Весь трафик', d.settings.domains.length + ' доменов · ' + d.settings.cidrs.length + ' IP сетей')
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
                    s.change ? node('p', 'at-footnote', label('Изменение: +' + s.change.added + ' / −' + s.change.removed + ' профилей; всего ' + s.change.total + (s.change.unchanged ? ' · без изменений' : ''))) : label(''),
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
            node('p', 'at-footnote', label('Заголовки хранятся только на роутере с настройками Atlas. Перенаправление на другой сервер запрещено, чтобы не переслать токен. После сохранения нажмите «Обновить».'))]), node('div', 'right', [E('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Сохранить', function() {
                return result(api.saveSubscription(sub.id || '', name.value, url.value, enabled.checked, headers.value, clearHeaders.checked)).then(function() { ui.hideModal(); return self.reload(); }).catch(function(e) { msg.textContent = e.message; });
            }, 'primary')])]);
    },
    bulkSubscriptionDialog: function() {
        var self = this;
        var content = node('textarea', 'at-input at-textarea', [], { rows: 10, spellcheck: 'false', placeholder: 'https://provider.example/sub/…\nРезерв | https://backup.example/sub/…\nhttps://provider.example/another' });
        var msg = node('div', 'at-bulk-results');
        ui.showModal('Массовый импорт подписок', [node('div', 'at-modal', [self.field('Одна HTTPS или Happ-ссылка на строку; можно «название | ссылка»', content), msg,
            node('p', 'at-footnote', label('Atlas сохранит до 64 источников, проверит URL и удалит дубликаты. Профили будут загружены после «Обновить все». Для авторизованных источников добавьте заголовки отдельно в настройках каждой подписки.'))]),
            node('div', 'right', [E('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Добавить источники', function() {
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
            node('div', 'right', [E('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Импортировать профили', function() {
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
            node('div', 'right', [E('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Удалить', function() { return result(api.deleteSubscription(sub.id)).then(function() { ui.hideModal(); return self.reload(); }); }, 'danger')])]);
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
        var strategy = node('select', 'at-input', [E('option', { value: 'fastest', selected: (s.auto_strategy || 'fastest') === 'fastest' }, 'Минимальный пинг'), E('option', { value: 'slowest', selected: s.auto_strategy === 'slowest' }, 'Максимальный пинг'), E('option', { value: 'stable', selected: s.auto_strategy === 'stable' }, 'Наиболее стабильный пинг')]);
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
            self.field('Название содержит', include, 'Любое из значений; пусто — без ограничения.'),
            self.field('Исключить по названию', exclude, 'Любое совпадение исключает узел. Без регулярных выражений.'),
            self.field('Проверять каждые, секунд', interval), self.field('Порог улучшения задержки, мс', tolerance, 'Уменьшает переключения при небольших колебаниях. Недоступный узел не удерживается этим порогом.'),
            node('label', 'at-checkbox', [interrupt, label('Разрывать текущие соединения при переключении')]),
            node('p', 'at-footnote', label('Обычно выключено: новые соединения идут через выбранный узел, текущие сохраняются. Включение может прервать звонки и загрузки. После 30 минут простоя проверки приостанавливаются до нового трафика.')),
            node('p', 'at-footnote', label('При нестандартных критериях группа блокируется до свежего подходящего замера; фильтры не расширяются. Для регулярных замеров без трафика через группу нужен Atlas Engine r2 или новее; возможность urltest.background показана ниже. Переключение разрывает старые соединения. FakeIP сохраняется в кеше; сохранённый выбор узла изолируется при каждом запуске службы.')), msg]),
            node('div', 'right', [E('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button(self.data.running ? 'Включить авто и применить' : 'Сохранить автовыбор', function() {
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
                    select.replaceChildren(E('option',{value:selected,selected:true},member ? member.name : 'Сохранённый профиль недоступен'));
                }
                compact();
                select.addEventListener('focus',function(){select.replaceChildren();(self.data.nodes || []).forEach(function(n){select.appendChild(E('option',{value:n.key,selected:n.key===reserves[index]},n.name));});if (!(self.data.nodes || []).some(function(n){return n.key===reserves[index];})) select.appendChild(E('option',{value:reserves[index],selected:true},'Сохранённый профиль недоступен'));});
                select.addEventListener('blur',compact);
                select.addEventListener('change',function(){reserves[index]=select.value;});
                list.appendChild(node('div','at-actions',[select,self.button('Выше',function(){if(index){var value=reserves[index-1];reserves[index-1]=reserves[index];reserves[index]=value;redraw();}},'ghost',index===0),self.button('Убрать',function(){reserves.splice(index,1);redraw();},'ghost')]));
            });
        }
        redraw();
        var mode=node('select','at-input at-download-mode',[E('option',{value:'default'},'Настройка движка'),E('option',{value:'off',disabled:features.indexOf('urltest.download_url')<0},'Выключено'),E('option',{value:'custom',disabled:features.indexOf('urltest.download_url')<0},'Свой адрес')]);
        mode.value=settings.urltest_download_check || 'default';
        var url=node('input','at-input at-download-url',[],{value:settings.urltest_download_url || '',placeholder:'https://example.com/test.bin'});
        var element=E('details',{},[E('summary',{},'Резервные серверы и проверка скачивания'),node('p','at-footnote',label('Резерв используется по порядку, когда нет основного сервера, подходящего по свежим замерам и вашим критериям. После восстановления группа возвращается к основным. Резервные серверы совместимы с приоритетом стран и порогами пинга. Проверка скачивания совместно с критериями Atlas требует Atlas Engine r3; перед переключением проверяется передача 64 КиБ через выбранный сервер. Для расширений нужен Atlas Engine.')),list,self.button('Добавить резервный сервер',function(){var available=(self.data.nodes || []).find(function(n){return reserves.indexOf(n.key)<0;});if(available){reserves.push(available.key);redraw();}},'ghost',features.indexOf('urltest.fallbacks')<0),self.field('Проверка скачивания 64 КиБ перед переключением',mode),self.field('Адрес файла для проверки',url),node('p','at-footnote',label('Расширения установленного движка: '+(features.join(', ') || 'не обнаружены')+'. Штатный sing-box сохраняет прежнее поведение. Сохранённые неподдерживаемые настройки требуют совместимого движка или очистки.'))]);
        return {element:element,values:function(){return {urltest_fallbacks:reserves.slice(),urltest_download_check:mode.value,urltest_download_url:mode.value==='custom' ? url.value.trim() : ''};}};
    },
    field: function(title, input, hint) { return node('label', 'at-field', [node('span', '', label(title)), input, hint ? node('small', '', label(hint)) : label('')]); },

    cloneSectionDialog: function(section) {
        var self=this,name=node('input','at-input at-clone-name',[],{value:(section.name+' копия').slice(0,48),maxlength:48});
        ui.showModal('Копировать сохранённую секцию',[self.field('Новое название',name),node('p','at-footnote',label('Будет скопирована последняя сохранённая версия. Копия выключена, имеет новый ID и не открывает прокси-порт. Несохранённые изменения формы не входят в копию.')),self.button('Создать копию',function(){return result(api.sectionClone(section.id,name.value.trim())).then(function(){ui.hideModal();return self.reload();});},'primary',self.busy())]);
    },
    plannerCard: function() {
        var self=this;
        function preview(validate){return result(api.configPreview(validate)).then(function(r){self.jsonDownloadDialog(validate?'Конфигурация проверена движком':'Предпросмотр конфигурации','atlas-config-preview.json',r.config,'Показаны сохранённые настройки. Секреты и произвольные поля протоколов скрыты. Служба и настройки не изменены. '+(r.conflicts.length ? 'Найдены перекрытия: '+r.conflicts.map(function(x){return x.section+' → '+x.earlier+' ('+x.domain+')';}).join('; ') : 'Перекрытия не найдены в первых 1000 простых доменных правил. Сложные правила и SRS требуют отдельной проверки.'));});}
        return node('section','at-card at-padded',[node('h3','',label('Проверка до применения')),node('p','at-footnote',label('Работает с сохранёнными настройками. Просмотрите конфигурацию, проверьте её установленным sing-box или объясните маршрут без сетевых запросов и перезапуска.')),node('div','at-actions',[self.button('Предпросмотр конфигурации',function(){return preview(false);},'ghost',self.busy()),self.button('Проверить без применения',function(){return preview(true);},'ghost',self.busy()),self.button('Объяснить маршрут',function(){self.routeExplainDialog();},'primary',self.busy())])]);
    },
    routeExplainDialog: function() {
        var self=this,fields={};
        [['domain','Домен','example.org'],['ip','Известный IP назначения','1.1.1.1'],['source_ip','IP устройства','192.168.1.25'],['port','Порт','443'],['inbound','Вход sing-box','tun']].forEach(function(x){fields[x[0]]=node('input','at-input at-explain-'+x[0],[],{value:x[0]==='port'?'443':x[0]==='inbound'?'tun':'',placeholder:x[2]});});
        var network=node('select','at-input at-explain-network',[E('option',{value:'tcp'},'TCP'),E('option',{value:'udp'},'UDP')]);
        var protocol=node('select','at-input at-explain-protocol',['tls','http','dns','quic',''].map(function(x){return E('option',{value:x},x||'Неизвестен');}));
        var output=node('div','at-explain-result');
        ui.showModal('Объяснение маршрута',[node('div','at-grid-2',Object.keys(fields).map(function(k){return self.field({domain:'Домен',ip:'IP назначения',source_ip:'IP устройства',port:'Порт',inbound:'Вход'}[k],fields[k]);}).concat([self.field('Транспорт',network),self.field('Распознанный протокол',protocol)])),node('p','at-footnote',label('Это разбор правил, а не сетевой тест. Для точного результата укажите известные IP и протокол. Без них и при бинарном SRS ответ может быть неопределённым.')),output,self.button('Показать маршрут',function(){var query={network:network.value,protocol:protocol.value};Object.keys(fields).forEach(function(k){if(fields[k].value.trim())query[k]=k==='port'?Number(fields[k].value):fields[k].value.trim();});return result(api.routeExplain(query)).then(function(r){output.replaceChildren(node('strong','',label(r.certain ? 'Маршрут: '+(r.action==='reject'?'Блокировать':r.outbound) : 'Неопределённо: не хватает данных для предыдущих правил')),node('pre','',label(JSON.stringify(r.trace,null,2))));});},'primary',self.busy())]);
    },

    sectionDialog: function(section, commit) {
        var self = this, original = Object.assign({}, section || {});
        function show(config) {
            var name = node('input', 'at-input at-section-name', [], { value: original.name || '', maxlength: 48 });
            var enabled = node('input', '', [], { type: 'checkbox', checked: original.enabled !== false });
            var policy = node('select', 'at-input at-section-policy', ['proxy','direct','exclude','block','interface'].map(function(x) { return E('option', { value: x, selected: x === (original.policy || 'proxy') }, {proxy:'Прокси',direct:'Напрямую',exclude:'Исключение',block:'Блокировать',interface:'VPN-интерфейс'}[x]); }));
            var pool = node('select', 'at-input at-section-pool', [E('option', { value: '', selected: !original.pool }, 'Общий пул / JSON outbound')].concat((self.data.subscriptions || []).filter(function(x) { return x.enabled; }).map(function(x) { return E('option', { value: x.id, selected: original.pool === x.id }, x.name); })));
            var iface = node('input', 'at-input at-section-interface', [], { value: original.interface || '', placeholder: 'wg0' });
            var resolver = node('input', 'at-input at-section-resolver', [], { value: original.resolver || '', placeholder: 'https://dns.example/dns-query' });
            var resolveIp = node('select','at-input at-section-resolve-ip',[E('option',{value:'inherit',selected:original.resolve_real_ip == null},'Наследовать общую настройку'),E('option',{value:'on',selected:original.resolve_real_ip === true},'Включить для этой секции'),E('option',{value:'off',selected:original.resolve_real_ip === false},'Выключить для этой секции')]);
            var autoInterval = node('input','at-input at-section-auto-interval',[],{type:'number',min:30,max:1800,value:original.auto_interval_seconds == null ? '' : original.auto_interval_seconds,placeholder:'Наследовать'});
            var autoTolerance = node('input','at-input at-section-auto-tolerance',[],{type:'number',min:1,max:2000,value:original.auto_tolerance_ms == null ? '' : original.auto_tolerance_ms,placeholder:'Наследовать'});
            var extensions = self.urltestExtensions(original);
            var autoUrl = node('input','at-input at-section-auto-url',[],{value:original.urltest_url || '',placeholder:'Наследовать общий HTTPS URL'});
            var sectionUot = node('select','at-input at-section-uot',[E('option',{value:'inherit',selected:original.udp_over_tcp == null},'Наследовать общую настройку'),E('option',{value:'on',selected:original.udp_over_tcp === true},'Включить'),E('option',{value:'off',selected:original.udp_over_tcp === false},'Выключить')]);
            var sectionUotVersion = node('select','at-input at-section-uot-version',[E('option',{value:'inherit',selected:original.udp_over_tcp_version == null},'Наследовать общую версию'),E('option',{value:'1',selected:original.udp_over_tcp_version === 1},'1'),E('option',{value:'2',selected:original.udp_over_tcp_version === 2},'2')]);
            var fields = {};
            ['domains','cidrs','source_ips','source_interfaces','ports','networks','exclude_domains','exclude_cidrs','exclude_source_ips'].forEach(function(k) { fields[k] = node('textarea', 'at-input at-textarea at-section-' + k, label((original[k] || []).join('\n')), { rows: 3, spellcheck: 'false' }); });
            var json = node('textarea', 'at-input at-textarea at-section-json', label(JSON.stringify(config || [], null, 2)), { rows: 12, spellcheck: 'false', autocomplete: 'off' });
            var listener = original.mixed_proxy || {};
            var mixed = node('input', 'at-section-mixed', [], { type: 'checkbox', checked: !!listener.enabled });
            var bind = node('input', 'at-input at-section-listen', [], { value: listener.listen || '127.0.0.1', placeholder: '192.168.1.1' });
            var port = node('input', 'at-input at-section-port', [], { type: 'number', min: 1024, max: 65535, value: listener.port || 2081 });
            var username = node('input', 'at-input at-section-username', [], { value: listener.username || '', autocomplete: 'off' });
            var password = node('input', 'at-input at-section-password', [], { type: 'password', autocomplete: 'new-password', placeholder: original.id ? 'Пусто — сохранить прежний пароль' : 'Не менее 12 символов' });
            var msg = node('p', 'at-inline-error');
            ui.showModal(original.name ? 'Изменить секцию' : 'Новая секция', [node('div', 'at-modal', [
                self.field('Название', name), node('label', 'at-checkbox', [enabled, label('Секция включена')]), self.field('Действие', policy), self.field('Пул подписки', pool), self.field('Исходящий VPN-интерфейс', iface),
                node('div', 'at-grid-2', [self.field('Домены', fields.domains), self.field('IP назначения / CIDR', fields.cidrs), self.field('IP устройств / CIDR', fields.source_ips), self.field('Входящие интерфейсы', fields.source_interfaces), self.field('Порты: 443,10000-20000', fields.ports), self.field('Транспорт: tcp,udp', fields.networks)]),
                self.field('DNS resolver для доменов', resolver), self.field('Разрешение реального IP',resolveIp),
                node('p','at-footnote',label('Отдельный DNS применяется к доменам секции независимо от портов и TCP/UDP соединений. Устройства и входящие интерфейсы учитываются, когда DNS-запрос сохраняет эти признаки. DNS-запрос не содержит порт будущего соединения.')),
                node('p','at-footnote',label('ID секций для экспертных связей: '+(self.data.settings.sections || []).map(function(x){return x.name+': '+x.id;}).join(' · '))),
                extensions.element,
                E('details',{},[E('summary',{},'UDP через TCP для этой секции'),self.field('UDP-over-TCP',sectionUot),self.field('Версия',sectionUotVersion),node('p','at-footnote',label('Для SOCKS и Shadowsocks обычного пула. Сервер должен поддерживать выбранную версию. Секция получает отдельные копии выходов; соседние секции сохраняют свои настройки. В экспертном JSON параметр задаётся в самом outbound.'))]),
                E('details',{},[E('summary',{},'Автопроверка серверов этой секции'),self.field('Интервал, секунд',autoInterval),self.field('Допустимая разница задержки, мс',autoTolerance),self.field('HTTPS URL проверки',autoUrl),node('p','at-footnote',label('Пустые поля наследуют общие значения. Для обычного прокси-пула заполненные поля создают независимый selector и URLTest. В экспертном JSON параметры URLTest задаются самим JSON.'))]),
                E('details',{},[E('summary',{},'Исключения только из этой секции'),node('div','at-grid-2',[self.field('Исключить домены',fields.exclude_domains),self.field('Исключить IP назначения / CIDR',fields.exclude_cidrs),self.field('Исключить устройства / CIDR',fields.exclude_source_ips)]),node('p','at-footnote',label('Исключённый трафик проверяется следующими правилами. Это не глобальный прямой маршрут. IP назначения проверяется по известному движку адресу; для доменов с FakeIP используйте доменные исключения.'))]),
                E('details', {}, [E('summary', {}, 'JSON outbound — расширенная конфигурация'), self.field('Объект, список или {"outbounds": […]}', json), node('p', 'at-footnote', label('Первый outbound — выход секции. Можно указать selector/urltest и связанные узлы с уникальными tag. Для связи с другой экспертной секцией используйте section_<ID секции>_<tag узла>. Несуществующие или выключенные выходы и циклы отвергаются при проверке конфигурации. Параметры протоколов проверяет установленный sing-box. Фильтры подписочного автовыбора к этому JSON не применяются. [] возвращает подписочный пул. Этот JSON может содержать пароли; доступен только администратору.'))]),
                node('label', 'at-checkbox', [mixed, label('Отдельный HTTP/SOCKS-прокси этой секции')]), node('div', 'at-grid-2', [self.field('LAN или loopback IP', bind), self.field('Порт', port), self.field('Имя пользователя', username), self.field('Пароль', password)]),
                node('p', 'at-footnote', label('Весь трафик этого HTTP/SOCKS-прокси использует выход секции. Порт должен быть уникальным. Изменения пока остаются в форме; затем сохраните правила и примените их.')), msg
            ]), node('div', 'right', [E('button', { 'class': 'btn', click: ui.hideModal }, 'Отмена'), self.button('Добавить в форму', function() {
                try {
                    var value = JSON.parse(json.value || '[]');
                    if (value && !Array.isArray(value) && value.outbounds && Object.keys(value).length === 1) value = value.outbounds;
                    if (!Array.isArray(value)) value = [value];
                    var updated = Object.assign({}, original, { name: name.value.trim(), enabled: enabled.checked, policy: policy.value, pool: pool.value, interface: iface.value.trim(), resolver: resolver.value.trim(), outbound_config: value, mixed_proxy: {enabled:mixed.checked,listen:bind.value.trim(),port:Number(port.value),username:username.value.trim(),password:password.value || listener.password || ''} });
                    updated.resolve_real_ip=resolveIp.value==='inherit' ? null : resolveIp.value==='on';
                    updated.udp_over_tcp=sectionUot.value==='inherit' ? null : sectionUot.value==='on';
                    updated.udp_over_tcp_version=sectionUotVersion.value==='inherit' ? null : Number(sectionUotVersion.value);
                    updated.auto_interval_seconds=autoInterval.value.trim() ? Number(autoInterval.value) : null;
                    updated.auto_tolerance_ms=autoTolerance.value.trim() ? Number(autoTolerance.value) : null;
                    updated.urltest_url=autoUrl.value.trim();
                    Object.assign(updated,extensions.values());
                    delete updated.outbound_config_set;
                    Object.keys(fields).forEach(function(k) { updated[k] = lines(fields[k].value); });
                    if (!updated.name) throw new Error('Введите название секции');
                    commit(updated); ui.hideModal();
                } catch (e) { msg.textContent = e.message || 'Проверьте JSON'; }
            }, 'primary')])]);
        }
        if (original.outbound_config_set && !original.outbound_config) return result(api.sectionDetails(original.id)).then(function(r) { show(r.outbound_config); });
        show(original.outbound_config || []);
        return Promise.resolve();
    },

    routingPage: function() {
        var self = this, d = self.data, s = d.settings;
        var mode = node('select', 'at-input', [E('option', { value: 'rules', selected: s.mode === 'rules' }, 'По правилам — остальное напрямую'), E('option', { value: 'global', selected: s.mode === 'global' }, 'Весь трафик — кроме исключений')]);
        var inputs = {};
        ['domains', 'cidrs', 'bypass_domains', 'bypass_cidrs'].forEach(function(k) { inputs[k] = node('textarea', 'at-input at-textarea', label(s[k].join('\n')), { rows: 6, spellcheck: 'false', placeholder: k.indexOf('domains') >= 0 ? 'example.org\nexample.net' : '203.0.113.0/24\n2001:db8::/32' }); });
        ['routed_source_ips', 'routing_excluded_ips'].forEach(function(k) { inputs[k] = node('textarea', 'at-input at-textarea', label((s[k] || []).join('\n')), { rows: 4, spellcheck: 'false', placeholder: '192.168.1.25/32\n2001:db8::25/128' }); });
        var blocked = node('textarea', 'at-input at-textarea', label((s.blocked_domains || []).join('\n')), { rows: 6, spellcheck: 'false', placeholder: 'ads.example\ntracker.example' });
        var sections = node('textarea', 'at-input at-textarea', label((s.sections || []).map(function(x) { return [x.name, x.policy, x.domains.join(','), x.cidrs.join(','), x.source_ips.join(','), x.pool || '', x.interface || '', x.resolver || '', (x.source_interfaces || []).join(','), (x.ports || []).join(','), (x.networks || []).join(',')].join(' | '); }).join('\n')), { rows: 7, spellcheck: 'false', placeholder: 'Работа | proxy | corp.example | | 192.168.1.25/32 | <ID подписки или пусто> | | | br-lan\nVPN intranet | interface | intranet.example | | | | wg0 | https://dns.example/dns-query |\nИсключить | exclude | local.example | | | | | |' });

        var sectionDraft = JSON.parse(JSON.stringify(s.sections || []));
        var sectionList = node('div', 'at-section-list');
        var serializedSections = '';
        function syncSections() {
            sections.value = sectionDraft.map(function(x) { return [x.name,x.policy,(x.domains || []).join(','),(x.cidrs || []).join(','),(x.source_ips || []).join(','),x.pool || '',x.interface || '',x.resolver || '',(x.source_interfaces || []).join(','),(x.ports || []).join(','),(x.networks || []).join(',')].join(' | '); }).join('\n');
            serializedSections = sections.value;
            sectionList.replaceChildren.apply(sectionList, sectionDraft.map(function(x, index) {
                function move(delta) { var other = index + delta; if (other < 0 || other >= sectionDraft.length) return; var saved=sectionDraft[index];sectionDraft[index]=sectionDraft[other];sectionDraft[other]=saved;syncSections(); }
                return node('article', 'at-card at-padded', [node('strong', '', label(x.name)), node('p', 'at-footnote', label((x.enabled === false ? 'Выключена · ' : '') + x.policy + (x.outbound_config_set || (x.outbound_config || []).length ? ' · JSON outbound' : '') + (x.mixed_proxy && x.mixed_proxy.enabled ? ' · HTTP/SOCKS ' + x.mixed_proxy.listen + ':' + x.mixed_proxy.port : ''))), node('div','at-actions',[
                    self.button('Изменить секцию', function() { return self.sectionDialog(x, function(value) { if(sectionDraft.some(function(y,i){return i!==index&&y.name.toLowerCase()===value.name.toLowerCase();})) throw new Error('Название секции уже используется');sectionDraft[index]=value;syncSections(); }); }, '', self.busy()),
                    self.button('Копировать сохранённую',function(){self.cloneSectionDialog(x);},'ghost',self.busy()||!x.id),
                    self.button('↑',function(){move(-1);},'ghost',index===0||self.busy()),self.button('↓',function(){move(1);},'ghost',index===sectionDraft.length-1||self.busy()),
                    self.button('Удалить из формы',function(){sectionDraft.splice(index,1);syncSections();},'danger-link',self.busy())
                ])]);
            }));
        }
        syncSections();
        var addSection = self.button('+ Секция', function() { return self.sectionDialog(null, function(value) { if(sectionDraft.some(function(x){return x.name.toLowerCase()===value.name.toLowerCase();})) throw new Error('Название секции уже используется');sectionDraft.push(value);syncSections(); }); }, 'primary', self.busy());

        var disableQuic = node('input', '', [], { type: 'checkbox', checked: !!s.disable_quic });
        var excludeNtp = node('input', '', [], { type: 'checkbox', checked: !!s.exclude_ntp });
        var blockDoh = node('input', '', [], { type: 'checkbox', checked: !!s.block_known_doh });
        var fetchListsViaProxy = node('input', 'at-fetch-lists-proxy', [], { type: 'checkbox', checked: !!s.fetch_lists_via_proxy });
        var fetchListsSubscription = node('select', 'at-input at-fetch-lists-subscription', [E('option', { value: '', selected: !s.fetch_lists_subscription }, 'Общий авто-пул')].concat((d.subscriptions || []).filter(function(x) { return x.enabled; }).map(function(x) { return E('option', { value: x.id, selected: s.fetch_lists_subscription === x.id }, x.name + ' · отдельный авто-пул'); })));
        var fetchListsSection = node('select','at-input at-fetch-section',[E('option',{value:'',selected:!s.fetch_lists_section},'Не использовать отдельную секцию')].concat((s.sections || []).filter(function(x) {return x.enabled !== false && ['proxy','interface','direct'].indexOf(x.policy)>=0;}).map(function(x) {return E('option',{value:x.id,selected:s.fetch_lists_section===x.id},x.name);} )));
        var listSectionChoices = {};
        var listPermissions = {};
        var listAssignments = node('div','', (s.remote_lists || []).map(function(item,index) {
            var select = node('select','at-input at-list-section',[E('option',{value:'',selected:!item.section},'Маршрут из списка')].concat((s.sections || []).filter(function(x) {return x.enabled !== false && ['proxy','interface','direct'].indexOf(x.policy)>=0;}).map(function(x) {return E('option',{value:x.id,selected:item.section===x.id},x.name);} )));
            listSectionChoices[item.id || String(index)] = select;
            var privateAccess = node('input','at-list-private',[],{type:'checkbox',checked:!!item.allow_private});
            var symlinks = node('input','at-list-symlinks',[],{type:'checkbox',checked:!!item.allow_symlinks});
            listPermissions[item.id || String(index)] = {privateAccess:privateAccess,symlinks:symlinks};
            return node('div','at-card at-padded',[
                self.field('Выход списка «' + item.name + '»',select,'Для назначения секции выберите политику proxy.'),
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
        var communitySelect = node('select', 'at-input at-community-catalog', communityLists.map(function(x) { return E('option', { value: x[0] }, x[1] + ' · ' + x[0]); }));
        var communityPolicy = node('select', 'at-input at-community-policy', [
            E('option', { value: 'proxy', selected: true }, 'Через общий прокси'), E('option', { value: 'direct' }, 'Напрямую'),
            E('option', { value: 'block' }, 'Блокировать'), E('option', { value: 'exclude' }, 'Исключить из прокси'), E('option', { value: 'interface' }, 'Через VPN интерфейс')
        ]);
        var communityIface = node('input', 'at-input at-community-interface', [], { placeholder: 'wg0 — только для VPN интерфейса' });
        var listMaxBytes = node('input','at-list-max-bytes',[],{type:'number',min:0,max:256,step:1,value:String((s.list_max_bytes == null ? 4194304 : s.list_max_bytes)/1048576)});
        var remoteLists = node('textarea', 'at-input at-textarea', label((s.remote_lists || []).map(function(x) { return [x.name, x.url, x.policy, x.format, x.enabled ? 'on' : 'off', x.id, x.interface || ''].join(' | '); }).join('\n')), { rows: 6, spellcheck: 'false', placeholder: 'EasyList | https://example.org/domains.txt | dnsblock | auto | on | |\nProxy rules | https://example.org/rules.json | proxy | json | on | |\nPrivate routes | https://example.org/routes.txt | proxy | cidrs | on | |' });
        var localTarget = node('select', 'at-input at-local-target', [E('option', { value: 'proxy' }, 'Через туннель'), E('option', { value: 'direct' }, 'Напрямую'), E('option', { value: 'block' }, 'Блокировать')]);
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
        return node('div', 'at-content', [self.sectionHead('Куда направлять трафик', 'Исключения имеют приоритет. Локальная сеть всегда доступна напрямую.'),
            self.plannerCard(),
            node('section','at-card at-padded',[node('h3','',label('Журнал службы')),node('p','at-footnote',label('Последние 200 строк Atlas из системного журнала. Доступны только администратору; могут содержать адреса и сведения о подключениях.')),self.button('Показать журнал',function(){return result(api.serviceLogs()).then(function(r){ui.showModal('Журнал Atlas',[node('pre','',label(r.content||'Записей нет')),node('p','at-footnote',label(r.truncated?'Показана последняя часть журнала.':'')),E('button',{'class':'btn',click:ui.hideModal},'Закрыть')]);});},'ghost',self.busy())]),
            node('section', 'at-card at-padded', [self.field('Режим маршрутизации', mode)]),
            node('div', 'at-grid-2', [node('section', 'at-card at-padded', [pill('ЧЕРЕЗ ТУННЕЛЬ', 'purple'), self.field('Домены', inputs.domains, 'По одному на строку. Поддомены включены.'), self.field('IP сети', inputs.cidrs, 'IPv4 и IPv6 в формате CIDR.')]), node('section', 'at-card at-padded', [pill('НАПРЯМУЮ', 'neutral'), self.field('Домены-исключения', inputs.bypass_domains), self.field('IP сети-исключения', inputs.bypass_cidrs)])]),
            node('div', 'at-grid-2', [node('section', 'at-card at-padded', [pill('УСТРОЙСТВА ЧЕРЕЗ ТУННЕЛЬ', 'purple'), self.field('IP устройств / сети', inputs.routed_source_ips, 'Укажите LAN IP устройства или подсеть в CIDR. Локальные адреса назначения остаются напрямую.')]), node('section', 'at-card at-padded', [pill('УСТРОЙСТВА В ОБХОД', 'neutral'), self.field('IP устройств / сети', inputs.routing_excluded_ips, 'Эти устройства используют прямое подключение даже в глобальном режиме.')])]),
            node('section', 'at-card at-padded', [node('h3', '', label('Независимые секции')), node('p', 'at-footnote', label('Создавайте правила по сайтам, устройствам, сетям, портам и транспорту. Выбирайте прокси, VPN, прямой маршрут или блокировку. Секции обрабатываются сверху вниз; исключения имеют приоритет.')), sectionList, addSection, E('details', {}, [E('summary', {}, 'Текстовый формат секций'), node('p','at-footnote',label('Поля через |: имя | действие | домены | CIDR | источник | пул | интерфейс | DNS | входящие интерфейсы | порты | tcp/udp. Для секций с портами/транспортом задавайте FakeIP отдельной доменной секцией. JSON outbound и настройки прокси сохраняются при совпадении имени.')), self.field('Секция на строку', sections)])]),
            node('section', 'at-card at-padded', [node('h3', '', label('Блокировка доменов')), node('p', '', label('DNS-блокировка по доменам. Укажите по одному на строку; устройства с собственным DoH могут обходить фильтр.')), self.field('Реклама, трекеры и другие домены', blocked)]),
            node('section', 'at-card at-padded', [node('h3', '', label('Импорт локального списка')), node('p', 'at-footnote', label('Загрузите UTF-8 файл .txt/.lst/.json размером до 4 МиБ. Записи проверяются на роутере; содержимое хранится только в правилах Atlas.')), self.field('Действие для правил', localTarget), self.field('Файл доменов / CIDR', localFile)]),
            node('section', 'at-card at-padded', [node('h3', '', label('Удалённые списки правил')), node('p', 'at-footnote', label('HTTP/HTTPS и локальные file:/// списки. Количество источников и записей не ограничено отдельным программным лимитом; учитывайте память роутера. Поддерживаются домены, hosts, CIDR, AdGuard DNS, sing-box JSON и SRS. SRS проверяется движком до сохранения; при ошибке загрузки остаётся прежняя рабочая версия. Параметры URL поддерживаются и скрыты в интерфейсе. Credentials запрещены. Локальным файлам расширение не требуется. JSON сохраняет все поддерживаемые движком поля и логические условия. Временные ошибки загрузки повторяются до трёх попыток. Для сохранённого адреса оставьте URL с /[saved].')), self.field('Максимальный размер файла, МиБ',listMaxBytes,'По умолчанию 4; 0 — без ограничения. Для больших списков требуется достаточно памяти.'), self.field('Каталог community lists', communitySelect), node('div', 'at-grid-2', [self.field('Маршрут каталога', communityPolicy), self.field('VPN интерфейс (если выбран)', communityIface)]), self.button('Добавить community list', addCommunityList, 'ghost', self.busy()), node('label', 'at-checkbox', [fetchListsViaProxy, label('Загружать и обновлять списки через прокси Atlas; при сбое прямого fallback нет')]), self.field('Подписка для обновления', fetchListsSubscription, 'Общий авто-пул или отдельный авто-пул подписки.'), self.field('Секция для обновления', fetchListsSection, 'Имеет приоритет над подпиской; после изменения примените настройки.'), node('p', 'at-footnote', label('Для этой опции Atlas должен быть запущен и настройки применены. Запросы идут через закрытый loopback HTTP proxy выбранного пула.')), self.field('Один список на строку: имя | HTTP/HTTPS URL или file:///путь | proxy/direct/exclude/interface/block/dnsblock | auto/domains/hosts/cidrs/adguard/json/srs | on/off | ID | интерфейс', remoteLists), listAssignments, listStatus]),
            node('section', 'at-card at-padded', [node('h3', '', label('Транспорт и синхронизация')), node('label', 'at-checkbox', [disableQuic, label('Блокировать QUIC (UDP/443), чтобы приложения переходили на TCP')]), node('label', 'at-checkbox', [excludeNtp, label('Направлять NTP (UDP/123) напрямую')]), node('label', 'at-checkbox', [blockDoh, label('Блокировать известные DoH серверы на устройствах')]), node('p', 'at-footnote', label('Блок QUIC действует на весь маршрутизируемый трафик. DoH-блокировка закрывает только известные домены; она не обнаруживает все пользовательские серверы.'))]),
            node('div', 'at-actions', [self.button('Сохранить правила', function() { var parsedSections = sections.value === serializedSections ? JSON.parse(JSON.stringify(sectionDraft)) : sections.value.split(/\r?\n/).map(function(x) { return x.trim(); }).filter(Boolean).map(function(line, i) { var parts = line.split('|').map(function(x) { return x.trim(); }); if (parts.length < 8 || parts.length > 11) throw new Error('Секция в строке ' + (i + 1) + ': нужно от 8 до 11 полей, разделённых символом |'); return Object.assign({}, sectionDraft.filter(function(x) { return x.name === parts[0]; })[0] || {}, { name: parts[0], policy: parts[1], domains: parts[2] ? parts[2].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], cidrs: parts[3] ? parts[3].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], source_ips: parts[4] ? parts[4].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], pool: parts[5], interface: parts[6], resolver: parts[7], source_interfaces: parts[8] ? parts[8].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], ports: parts[9] ? parts[9].split(',').map(function(x) { return x.trim(); }).filter(Boolean) : [], networks: parts[10] ? parts[10].split(',').map(function(x) { return x.trim().toLowerCase(); }).filter(Boolean) : [] }); }); var parsedLists = remoteLists.value.split(/\r?\n/).map(function(x) { return x.trim(); }).filter(Boolean).map(function(line, i) { var parts = line.split('|').map(function(x) { return x.trim(); }); if (parts.length !== 6 && parts.length !== 7) throw new Error('Список в строке ' + (i + 1) + ': нужно 6 или 7 полей, разделённых символом |'); return { name: parts[0], url: parts[1], policy: parts[2], format: parts[3], enabled: parts[4] === 'on', id: parts[5] || undefined, interface: parts[6] || '', section: listSectionChoices[parts[5] || String(i)] ? listSectionChoices[parts[5] || String(i)].value : '', allow_private: !!(listPermissions[parts[5] || String(i)] && listPermissions[parts[5] || String(i)].privateAccess.checked), allow_symlinks: !!(listPermissions[parts[5] || String(i)] && listPermissions[parts[5] || String(i)].symlinks.checked) }; }); var settings = Object.assign({}, s, { mode: mode.value, blocked_domains: lines(blocked.value), remote_lists: parsedLists, list_max_bytes:Math.round(Number(listMaxBytes.value)*1048576), fetch_lists_via_proxy: fetchListsViaProxy.checked, fetch_lists_subscription: fetchListsSection.value ? '' : fetchListsSubscription.value, fetch_lists_section: fetchListsSection.value, disable_quic: disableQuic.checked, exclude_ntp: excludeNtp.checked, block_known_doh: blockDoh.checked, sections: parsedSections }); Object.keys(inputs).forEach(function(k) { settings[k] = lines(inputs[k].value); }); return result(api.saveSettings(settings)).then(function() { ui.addNotification(null, node('p', '', label('Правила сохранены. Примените их в обзоре.')), 'info'); return self.reload(); }); }, 'primary', self.busy())]),
            node('p', 'at-footnote', label('Доменные правила используют DNS и распознавание TLS/HTTP/QUIC. Клиентский DoH и ECH могут скрывать домен: для таких назначений используйте IP правила или режим всего трафика.'))]);
    },

    jsonDownloadDialog: function(title, filename, data, notice) {
        var content = JSON.stringify(data, null, 2);
        var box = node('textarea', 'at-input at-textarea', label(content), { rows: 15, readonly: true, spellcheck: 'false' });
        ui.showModal(title, [node('div','at-modal',[node('p','at-footnote',label(notice)),box]),node('div','right',[
            E('button', {'class':'btn',click:ui.hideModal}, 'Закрыть'), this.button('Скачать JSON',function(){
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
            E('button',{'class':'btn',click:ui.hideModal},'Отмена'),self.button('Восстановить настройки',function(){return result(api.restoreBackup(content.value)).then(function(){ui.hideModal();return self.reload();}).catch(function(e){msg.textContent=e.message;});},'primary',self.data.running||self.busy())
        ])]);
    },

    settingsPage: function() {
        var self = this, d = self.data;
        var interval = node('input', 'at-input', [], { type: 'number', min: 1, max: 168, value: d.settings.interval_hours });
        var maxActive = node('select', 'at-input at-max-active', [128,256,512,1024,0].map(function(n) { return E('option', { value: String(n), selected: Number(d.settings.max_active_nodes == null ? 512 : d.settings.max_active_nodes) === n }, n ? String(n) + ' профилей' : 'Без лимита активного пула'); }));
        var dnsFilter = node('select', 'at-input', [E('option', { value: 'cloudflare', selected: d.settings.dns_filter === 'cloudflare' }, 'Cloudflare DoH'), E('option', { value: 'adguard', selected: d.settings.dns_filter === 'adguard' }, 'AdGuard DoH — реклама и трекеры'), E('option', { value: 'custom', selected: d.settings.dns_filter === 'custom' }, 'Свой DNS')]);
        var yacdEnabled = node('input','at-yacd-enabled',[],{type:'checkbox',checked:!!d.settings.yacd_enabled});
        var yacdWan = node('input','at-yacd-wan',[],{type:'checkbox',checked:!!d.settings.yacd_wan});
        var yacdListen = node('input','at-input at-yacd-listen',[],{value:d.settings.yacd_listen || '127.0.0.1'});
        var dnsType = node('select', 'at-input', [E('option', { value: 'https', selected: d.settings.custom_dns_type === 'https' }, 'DoH (HTTPS)'), E('option', { value: 'tls', selected: d.settings.custom_dns_type === 'tls' }, 'DoT (TLS)'), E('option', { value: 'udp', selected: d.settings.custom_dns_type === 'udp' }, 'UDP (без шифрования)')]);
        var dnsServer = node('input', 'at-input', [], { value: d.settings.custom_dns_server || '', placeholder: '1.1.1.1 или dns.example.net' });
        var dnsSni = node('input', 'at-input', [], { value: d.settings.custom_dns_sni || '', placeholder: 'dns.example.net' });
        var dnsPath = node('input', 'at-input', [], { value: d.settings.custom_dns_path || '/dns-query', placeholder: '/dns-query' });
        var fakeip = node('input', '', [], { type: 'checkbox', checked: !!d.settings.fakeip });
        var fakeipTtl = node('input', 'at-input', [], { type: 'number', min: 1, max: 86400, value: d.settings.fakeip_ttl_seconds || 60 });
        var resolveRealIp = node('input', '', [], { type: 'checkbox', checked: !!d.settings.resolve_real_ip });
        var killSwitch = node('input', '', [], { type: 'checkbox', checked: !!d.settings.kill_switch });
        var bootstrapDnsType = node('select', 'at-input at-bootstrap-type', [E('option', { value: 'https', selected: (d.settings.bootstrap_dns_type || 'https') === 'https' }, 'DoH (HTTPS)'), E('option', { value: 'tls', selected: d.settings.bootstrap_dns_type === 'tls' }, 'DoT (TLS)'), E('option', {value:'udp',selected:d.settings.bootstrap_dns_type === 'udp'},'UDP (без шифрования)')]);
        var bootstrapDnsServer = node('input', 'at-input', [], { value: d.settings.bootstrap_dns_server || '1.1.1.1', placeholder: '1.1.1.1' });
        var bootstrapDnsSni = node('input', 'at-input', [], { value: d.settings.bootstrap_dns_sni || 'cloudflare-dns.com', placeholder: 'cloudflare-dns.com' });
        var bootstrapDnsPath = node('input', 'at-input', [], { value: d.settings.bootstrap_dns_path || '/dns-query', placeholder: '/dns-query' });
        var udpOverTcp = node('input', '', [], { type: 'checkbox', checked: !!d.settings.udp_over_tcp });
        var udpOverTcpVersion = node('select', 'at-input', [E('option', { value: '2', selected: Number(d.settings.udp_over_tcp_version || 2) === 2 }, 'Версия 2'), E('option', { value: '1', selected: Number(d.settings.udp_over_tcp_version || 2) === 1 }, 'Версия 1')]);
        var interfaceMonitoring = node('input', '', [], { type: 'checkbox', checked: !!d.settings.interface_monitoring });
        var monitoredInterfaces = node('input', 'at-input', [], { value: (d.settings.monitored_interfaces || []).join(', '), placeholder: 'wan, wan6' });
        var interfaceDelay = node('input','at-input at-interface-delay',[],{type:'number',min:0,max:60000,value:d.settings.interface_reload_delay_ms == null ? 2000 : d.settings.interface_reload_delay_ms});
        var defaultInterface = node('select', 'at-input', [E('option', { value: '', selected: !d.settings.default_interface }, 'Автоматически (маршрут по умолчанию)')].concat((d.interfaces || []).filter(function(x) { return x !== 'lo' && x !== 'atlas0'; }).map(function(x) { return E('option', { value: x, selected: d.settings.default_interface === x }, x); })));
        var logLevel = node('select', 'at-input', ['error','warn','info','debug'].map(function(x) { return E('option', { value: x, selected: (d.settings.log_level || 'warn') === x }, x); }));
        var mixedEnabled = node('input', '', [], { type: 'checkbox', checked: !!d.settings.mixed_proxy_enabled });
        var mixedAddress = node('input', 'at-input', [], { value: d.settings.mixed_proxy_listen || '', placeholder: '192.168.1.1' });
        var mixedPort = node('input', 'at-input', [], { type: 'number', min: 1024, max: 65535, value: d.settings.mixed_proxy_port || 2080 });
        var mixedUser = node('input', 'at-input', [], { value: d.settings.mixed_proxy_username || '', placeholder: 'atlas-client', maxlength: 64 });
        var mixedPass = node('input', 'at-input', [], { type: 'password', autocomplete: 'new-password', placeholder: 'Оставьте пустым, чтобы сохранить пароль' });
        var dhcpDns = node('input', '', [], { type: 'checkbox', checked: !!d.settings.dhcp_dns_enabled });
        var configStorage = node('select', 'at-input at-config-storage', [E('option', { value: 'flash', selected: (d.settings.config_storage || 'flash') === 'flash' }, 'Flash — сохранять между перезагрузками'), E('option', { value: 'ram', selected: d.settings.config_storage === 'ram' }, 'RAM — уменьшить запись во flash')]);
        configStorage.appendChild(E('option',{value:'external',selected:d.settings.config_storage==='external'},'USB / внешний накопитель'));
        var configDir = node('input','at-input at-config-dir',[],{value:d.settings.config_custom_dir || '',placeholder:'/mnt/usb/atlas'});
        var cacheStorage = node('select', 'at-input', [E('option', { value: 'flash', selected: (d.settings.cache_storage || 'flash') === 'flash' }, 'Flash'), E('option', { value: 'ram', selected: d.settings.cache_storage === 'ram' }, 'RAM'), E('option', { value: 'external', selected: d.settings.cache_storage === 'external' }, 'USB/внешнее хранилище')]);
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
                self.button(d.running ? 'Сохранить и применить' : 'Сохранить настройки', function() { var safeLists = (d.settings.remote_lists || []).map(function(x) { return { id: x.id, name: x.name, url: x.url, policy: x.policy, format: x.format, enabled: x.enabled, interface: x.interface || '', section:x.section || '', allow_private:!!x.allow_private, allow_symlinks:!!x.allow_symlinks }; }); return result(api.saveSettings(Object.assign({}, d.settings, { remote_lists: safeLists, yacd_enabled:yacdEnabled.checked, yacd_wan:yacdWan.checked, yacd_listen:yacdListen.value.trim(), interval_hours: Number(interval.value), max_active_nodes: Number(maxActive.value), dns_filter: dnsFilter.value, custom_dns_type: dnsType.value, custom_dns_server: dnsServer.value.trim(), custom_dns_sni: dnsSni.value.trim(), custom_dns_path: dnsPath.value.trim(), bootstrap_dns_type: bootstrapDnsType.value, bootstrap_dns_server: bootstrapDnsServer.value.trim(), bootstrap_dns_sni: bootstrapDnsSni.value.trim(), bootstrap_dns_path: bootstrapDnsPath.value.trim(), udp_over_tcp: udpOverTcp.checked, udp_over_tcp_version: Number(udpOverTcpVersion.value), interface_monitoring: interfaceMonitoring.checked, monitored_interfaces: lines(monitoredInterfaces.value), interface_reload_delay_ms:Number(interfaceDelay.value), default_interface: defaultInterface.value, log_level: logLevel.value, fakeip: fakeip.checked, browser_diagnostics: fakeip.checked && !!d.settings.browser_diagnostics, fakeip_ttl_seconds: Number(fakeipTtl.value), resolve_real_ip: resolveRealIp.checked, kill_switch: killSwitch.checked, dhcp_dns_enabled: dhcpDns.checked, config_storage: configStorage.value, config_custom_dir:configStorage.value === 'external' ? configDir.value.trim() : '', cache_storage: cacheStorage.value, cache_custom_path: cacheStorage.value === 'external' ? cachePath.value.trim() : '', mixed_proxy_enabled: mixedEnabled.checked, mixed_proxy_listen: mixedAddress.value.trim(), mixed_proxy_port: Number(mixedPort.value), mixed_proxy_username: mixedUser.value.trim(), mixed_proxy_password: mixedPass.value }))).then(function() { return d.running ? self.action('apply') : self.reload(); }).then(function() { ui.addNotification(null, node('p', '', label('Настройки сохранены')), 'info'); }); }, 'primary', self.busy())]),
            node('section', 'at-card at-padded', [node('h3', '', label('Резервная копия и диагностика')), node('div','at-actions',[self.button('Экспорт настроек',function(){return self.backupExport();},'',self.busy()),self.button('Восстановить из копии',function(){self.backupRestoreDialog();},'',self.busy()||d.running),self.button('Диагностический отчёт',function(){return self.diagnosticExport();},'',self.busy())]), node('p','at-footnote',label('Для восстановления остановите службу в обзоре. Резервная копия содержит секреты; диагностический отчёт их исключает.'))]),
            node('section', 'at-card at-padded', [node('h3', '', label('Система')), node('dl', 'at-details', [node('dt', '', label('Atlas')), node('dd', '', label(d.version + ' beta')), node('dt', '', label('Движок')), node('dd', '', label(d.engine || 'Не установлен')), node('dt', '', label('Применение')), node('dd', '', label(d.applied.at ? date(d.applied.at) : 'Не применялось')), node('dt', '', label('Watchdog')), node('dd', '', label(d.watchdog && d.watchdog.reason ? d.watchdog.reason + ' · ' + date(d.watchdog.at) : 'Ошибок восстановления нет')), node('dt', '', label('Конфигурация')), node('dd', '', label('sing-box check + ограниченный откат к последней рабочей конфигурации'))])]),
            node('p', 'at-footnote', label('Atlas управляет собственным экземпляром sing-box. Одновременная работа с Podkop, Passwall или OpenClash блокируется. Ссылка подписки не показывается в статусе или журнале Atlas.'))]);
    },
    monitorPage: function() {
        var self = this, m = self.monitor || {}, connections = m.connections || [], rules = m.rules || [];
        return node('div', 'at-content', [
            self.sectionHead('Монитор соединений', 'Снимок локального API sing-box. Данные доступны только администраторам LuCI и не отправляются наружу.',
                self.button('Обновить', function() { return result(api.monitor()).then(function(data) { self.monitor = data; self.draw(); }); }, 'small', self.busy())),
            !m.available ? node('div', 'at-notice', label(m.message || 'Загрузка данных монитора…')) : label(''),
            node('div', 'at-stats', [
                self.stat('СОЕДИНЕНИЯ', String(connections.length), m.truncated ? 'Часть потоков и правил скрыта' : 'Активные потоки'),
                self.stat('ОТДАНО', bytes(m.upload_total), 'Счётчик процесса sing-box'),
                self.stat('ПОЛУЧЕНО', bytes(m.download_total), 'Счётчик процесса sing-box'),
                self.stat('ПАМЯТЬ', m.memory && m.memory.inuse ? bytes(m.memory.inuse) : '—', m.memory && m.memory.oslimit ? 'лимит ' + bytes(m.memory.oslimit) : 'sing-box')
            ]),
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
    clientPrivacyTest: function() {
        var self = this;
        self.clientPrivacy = ['Проверка выполняется…'];
        self.draw();
        function publicIP(host, family) {
            var controller = new AbortController(), timer = setTimeout(function() { controller.abort(); }, 8000);
            return fetch('https://' + host + '/?format=json', { signal: controller.signal, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' })
                .then(function(r) { if (!r.ok) throw new Error('HTTP'); return r.json(); })
                .then(function(r) {
                    if (!r || typeof r.ip !== 'string' || r.ip.length > 45 || !/^[0-9a-fA-F:.]+$/.test(r.ip)) throw new Error('IP');
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
                    resolve('WebRTC без STUN: ' + (addresses.length ? 'локальные ICE адреса: ' + addresses.join(', ') : 'адреса не получены; это не доказывает отсутствие утечек'));
                }
                try {
                    pc = new RTCPeerConnection({ iceServers: [] });
                    timer = setTimeout(done, 4000);
                    pc.onicecandidate = function(event) {
                        if (!event.candidate) { done(); return; }
                        var address = event.candidate.address;
                        if (!address) { var fields = event.candidate.candidate.split(' '); address = fields[4]; }
                        if (address && /^[a-zA-Z0-9:.\-]{1,253}$/.test(address) && addresses.indexOf(address) < 0 && addresses.length < 16) addresses.push(address);
                    };
                    pc.createDataChannel('atlas-local-check');
                    pc.createOffer().then(function(offer) { return pc.setLocalDescription(offer); }).catch(done);
                } catch (e) { done(); }
            });
        }
        return Promise.all([publicIP('api.ipify.org', 'IPv4'), publicIP('api6.ipify.org', 'IPv6'), rtc()]).then(function(results) {
            self.clientPrivacy = results; self.draw();
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
        return node('div', 'at-content', [this.sectionHead('Проверка приватности', 'Аудит активной конфигурации Atlas.'),
            node('section','at-card at-padded',[node('h3','',label('Firewall и маршрутизация')),node('p','at-footnote',label('Читает таблицы и правила nftables, маршруты IPv4/IPv6 и правила выбора таблиц. Отчёт содержит сетевые адреса и доступен администратору.')),self.button('Проверить nftables',function(){return result(api.nftDiagnostics()).then(function(r){ui.showModal('Диагностика nftables',[node('div','',r.checks.map(function(c){return node('p','',label((c.ok?'OK · ':'ПРОВЕРИТЬ · ')+c.label));})),node('pre','',label(JSON.stringify(r,null,2))),E('button',{'class':'btn',click:ui.hideModal},'Закрыть')]);});},'ghost',self.busy())]),
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
            node('section', 'at-card at-padded', [node('h3', '', label('Ограничения проверки')), node('p', 'at-footnote', label('Atlas не видит собственный DoH/VPN клиента и не обещает анонимность. В режиме «По правилам» трафик вне заданных правил идёт напрямую. Для защиты всей сети выберите глобальный режим и дополнительно проверьте соединение с клиентского устройства.'))])]);
    }
});
