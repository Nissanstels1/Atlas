"""Read-only rule inspection. Unknown inputs remain unknown, never a guessed route."""
import copy
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit
from core import AtlasError, host


def safe_config(config):
    def clean(value, key=''):
        if re.search(r'password|secret|token|uuid|private.key|authorization|credential', key, re.I):
            return '[hidden]'
        if isinstance(value, dict):return {k:clean(v,k) for k,v in value.items()}
        if isinstance(value, list):return [clean(v,key) for v in value]
        if isinstance(value,str) and value.startswith(('https://','http://')):
            p=urlsplit(value)
            return urlunsplit((p.scheme,p.hostname or '',p.path,'',''))
        return value
    result=clean(copy.deepcopy(config))
    # Arbitrary administrator JSON can put credentials in non-standard fields.
    visible={'type','tag','server','server_port','bind_interface','outbounds','fallbacks','default','interval','tolerance','interrupt_exist_connections'}
    result['outbounds']=[{k:v for k,v in out.items() if k in visible} for out in result.get('outbounds',[])]
    for inbound in result.get('inbounds',[]):inbound.pop('users',None)
    return result


def validated_query(value):
    allowed={'domain','ip','source_ip','port','network','protocol','inbound'}
    if not isinstance(value,dict) or set(value)-allowed:raise AtlasError('Некорректные поля проверки маршрута')
    q=dict(value)
    if q.get('domain'):
        if not isinstance(q['domain'],str):raise AtlasError('Домен должен быть строкой')
        q['domain']=host(q['domain'].strip().removeprefix('*.'))
    for key in ('ip','source_ip'):
        if q.get(key):
            try:q[key]=str(ipaddress.ip_address(q[key]))
            except ValueError as exc:raise AtlasError('Укажите корректный IP') from exc
    if q.get('port') not in ('',None):
        if type(q['port']) is not int or not 1<=q['port']<=65535:raise AtlasError('Порт должен быть 1–65535')
    else:q.pop('port',None)
    if q.get('network') not in ('tcp','udp'):raise AtlasError('Выберите TCP или UDP')
    if q.get('protocol','') not in ('','http','tls','dns','quic'):raise AtlasError('Некорректный протокол')
    if not isinstance(q.get('inbound',''),str) or len(q.get('inbound',''))>64:raise AtlasError('Некорректный вход')
    if not any(q.get(x) for x in ('domain','ip','source_ip')):raise AtlasError('Укажите домен или IP')
    return q


def combine(values, mode):
    if mode=='or':return True if True in values else None if None in values else False
    return False if False in values else None if None in values else True


def match_rule(rule,q,sets):
    if rule.get('type')=='logical':
        result=combine([match_rule(x,q,sets) for x in rule['rules']],rule['mode'])
    else:
        values=[];groups={}
        for key,value in rule.items():
            if key in ('action','outbound','server','type','invert','strategy','timeout','override_port'):continue
            choices=value if isinstance(value,list) else [value]
            if key in ('domain','domain_suffix'):
                domain=q.get('domain');values.append(None if not domain else any(domain==x or (key=='domain_suffix' and domain.endswith('.'+x)) for x in choices))
            elif key in ('ip_cidr','source_ip_cidr'):
                address=q.get('ip' if key=='ip_cidr' else 'source_ip')
                values.append(None if not address else any(ipaddress.ip_address(address) in ipaddress.ip_network(x) for x in choices))
            elif key in ('network','protocol','inbound'):
                values.append(None if not q.get(key) else q[key] in choices)
            elif key in ('port','port_range'):
                port=q.get('port');values.append(None if port is None else (port in choices if key=='port' else any(int(x.split(':')[0])<=port<=int(x.split(':')[1]) for x in choices)))
            elif key=='ip_is_private':
                # sing-box private ranges; benchmarking/FakeIP are not private routes.
                address=q.get('ip');ranges=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','fc00::/7','fe80::/10','::1/128']
                if not address:values.append(None)
                else:
                    addr=ipaddress.ip_address(address)
                    private=any(addr in ipaddress.ip_network(x) for x in ranges)
                    values.append(private==bool(value) if private or (addr.is_global and not addr.is_multicast) else None)
            elif key=='rule_set':values.append(combine([match_rule(sets[x],q,sets) if x in sets else None for x in choices],'or'))
            else:values.append(None)
            category = 'destination' if key in ('domain','domain_suffix','domain_keyword','domain_regex','geosite','geoip','ip_cidr','ip_is_private') else 'port' if key in ('port','port_range') else 'source' if key in ('source_ip_cidr','source_geoip','source_ip_is_private') else key
            groups.setdefault(category,[]).append(values.pop())
        result=combine([combine(items,'or') for items in groups.values()],'and')
    return not result if rule.get('invert') and result is not None else result


def explain_route(config,query):
    q=validated_query(query)
    sets={x['tag']:{'type':'logical','mode':'or','rules':x['rules']} for x in config['route'].get('rule_set',[]) if x.get('type')=='inline'}
    trace=[];uncertain=False
    for i,rule in enumerate(config['route']['rules']):
        if rule.get('action') in ('sniff','resolve','route-options'):continue
        matched=match_rule(rule,q,sets)
        if matched is False:continue
        trace.append({'index':i,'match':'unknown' if matched is None else 'yes','action':rule.get('action','route'),'outbound':rule.get('outbound','')})
        if matched is None:uncertain=True;continue
        return {'query':q,'certain':not uncertain,'outbound':None if uncertain else rule.get('outbound'), 'action':None if uncertain else rule.get('action','route'),'trace':trace,'candidate':rule.get('outbound')}
    return {'query':q,'certain':not uncertain,'outbound':None if uncertain else config['route']['final'],'action':None if uncertain else 'route','trace':trace,'candidate':config['route']['final']}


def conflicts(settings):
    issues=[];rows=[x for x in settings['sections'] if x['enabled']]
    seen={};checked=0
    for section in sorted(rows,key=lambda x:x['policy']!='exclude'):
        if any(section[k] for k in ('cidrs','source_ips','source_interfaces','ports','networks')) or section.get('exclude_domains') or section.get('exclude_cidrs') or section.get('exclude_source_ips'):continue
        for domain in section['domains']:
            if checked>=1000:return issues
            checked+=1
            prior=next((v for k,v in seen.items() if domain==k or domain.endswith('.'+k)),None)
            if prior and prior['id']!=section['id']:
                issues.append({'kind':'shadowed-domain','section':section['name'],'earlier':prior['name'],'domain':domain})
            else:seen.setdefault(domain,section)
            if len(issues)>=256:return issues
    return issues
