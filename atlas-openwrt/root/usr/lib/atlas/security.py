"""Classify client observations without logging or storing their IP addresses."""
import hashlib,ipaddress,time

def fingerprint(value):return hashlib.sha256(str(ipaddress.ip_address(value)).encode()).hexdigest()

def uniform_proxy_expected(settings,active_config=None):
    if settings.get('mode')!='global':return False
    if any(settings.get(k) for k in ('bypass_domains','bypass_cidrs','routing_excluded_ips')):return False
    if any(x.get('enabled',True) and x.get('policy') in ('direct','exclude','interface') for x in settings.get('sections',[])+settings.get('remote_lists',[])):return False
    if active_config is not None:
        route=active_config.get('route',{})
        if route.get('final')!='proxy':return False
        direct={x.get('tag') for x in active_config.get('outbounds',[]) if x.get('type')=='direct'}
        for rule in route.get('rules',[]):
            if rule.get('outbound') in direct and not rule.get('ip_is_private') and rule.get('port')!=123 and rule.get('port')!=[123]:return False
    return True

def compare_client(observations,baseline,mode,generation,now=None):
    if not isinstance(observations,dict) or set(observations)-{'ipv4','ipv6','webrtc','stun'}:raise ValueError('Некорректные результаты браузера')
    rtc=observations.get('webrtc',[])
    if not isinstance(rtc,list) or len(rtc)>16 or type(observations.get('stun',False)) is not bool:raise ValueError('Некорректный результат WebRTC')
    now=int(time.time() if now is None else now)
    fresh=baseline.get('status')=='done' and type(baseline.get('checked')) is int and 0<=now-baseline['checked']<=600 and baseline.get('generation')==generation
    rows=[]
    for family,key in [(4,'ipv4'),(6,'ipv6')]:
        value=observations.get(key,'')
        if not isinstance(value,str) or len(value)>45:raise ValueError('Некорректный адрес браузера')
        state='unknown';message='Ответ сервиса не получен; отсутствие ответа не подтверждает защиту.'
        if value:
            address=ipaddress.ip_address(value)
            if address.version!=family:raise ValueError('Неверное семейство адреса')
            identity=fingerprint(value)
            proxy=baseline.get('proxy_'+key+'_sha256') if fresh else None
            direct=baseline.get('direct_'+key+'_sha256') if fresh else None
            if proxy and direct and proxy==direct:message='Прокси и прямой выход совпали; разделение маршрутов не подтверждено.'
            elif proxy and identity==proxy:state='match';message='Выход браузера совпадает с измеренным выходом общего прокси.'
            elif proxy and direct and identity==direct:state='leak' if mode=='global' else 'direct';message='Браузер использует прямой выход роутера. Проверьте исключения и ожидаемый маршрут.'
            elif proxy:state='different';message='Выход отличается: возможны другая группа, клиентский VPN или обход. Проверьте ожидаемый маршрут.'
            else:message='Адрес получен, но свежий выход прокси этого семейства не измерен.'
        rows.append(dict(id=key,state=state,message=message))
    public=[]
    for value in rtc:
        if not isinstance(value,str) or len(value)>253:raise ValueError('Некорректный ICE адрес')
        if value.endswith('.local'):continue
        address=ipaddress.ip_address(value)
        if address.is_global:public.append(address)
    exposed=any(fresh and baseline.get('proxy_ipv%d_sha256'%x.version) and fingerprint(str(x))==baseline.get('direct_ipv%d_sha256'%x.version) and baseline.get('direct_ipv%d_sha256'%x.version)!=baseline.get('proxy_ipv%d_sha256'%x.version) for x in public)
    rows.append(dict(id='webrtc',state=('leak' if mode=='global' else 'direct') if exposed else 'unknown',message='WebRTC раскрывает измеренный прямой IP роутера.' if exposed else 'Прямой IP не подтверждён; отсутствие ICE кандидатов не доказывает отсутствие утечки.'))
    rows.append(dict(id='dns',state='unchecked',message='Внешняя утечка DNS/DoH этим тестом не измеряется. Выполните отдельную проверку DNS с устройства.'))
    return {'ok':True,'baseline_fresh':fresh,'checks':rows,'has_confirmed_leak':any(x['state']=='leak' for x in rows),'notice':'Результат относится к этому браузеру и общему выходу. В режиме групп прямой маршрут может быть намеренным. Это не оценка полной анонимности.'}
