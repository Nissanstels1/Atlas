"""Read-only nftables and policy-routing inspection for administrator diagnostics."""
import json
import time
import subprocess

def inspect(run, config):
    checks=[]; tables=[]; details={}
    commands={
        'nft':['/usr/sbin/nft','-j','list','ruleset'],
        'ipv4_rules':['/sbin/ip','-4','rule','show'],
        'ipv6_rules':['/sbin/ip','-6','rule','show'],
        'ipv4_routes':['/sbin/ip','-4','route','show','table','all'],
        'ipv6_routes':['/sbin/ip','-6','route','show','table','all']}
    for name, command in commands.items():
        try:
            result=run(command,10)
            content=result.stdout.decode('utf-8','replace')
            details[name]={'ok':result.returncode==0,'content':content[:262144], 'truncated':len(content)>262144}
        except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
            details[name]={'ok':False,'content':type(exc).__name__,'truncated':False}
    nft=details['nft']
    entries=[]
    if nft['ok'] and not nft['truncated']:
        try:entries=json.loads(nft['content']).get('nftables',[])
        except (ValueError,AttributeError):nft['ok']=False
    for entry in entries:
        if 'table' in entry:tables.append(entry['table'])
    checks.append({'id':'nft','ok':nft['ok'] and not nft['truncated'],'label':'nftables JSON доступен'})
    checks.append({'id':'fw4','ok':any(x.get('name')=='fw4' for x in tables),'label':'Таблица firewall4 присутствует'})
    for inbound in config.get('inbounds',[]):
        if inbound.get('type')!='tun':continue
        interface=inbound['interface_name']
        related=[e for e in entries if any(interface in json.dumps(v) for v in e.values())]
        tables_for_tun=[x for x in tables if interface in x.get('name','')]
        capture_ok=bool(related or tables_for_tun) if inbound.get('auto_redirect') else bool(inbound.get('include_interface')) and all(i in details['ipv4_rules']['content'] or i in details['ipv6_rules']['content'] for i in inbound.get('include_interface',[]))
        checks.append({'id':interface,'ok':capture_ok,'label':'Перехват '+interface,
                       'expected_interfaces':inbound.get('include_interface',[]), 'related_entries':len(related)})
        checks.append({'id':interface+'-routes','ok':any(interface in details[k]['content'] for k in ('ipv4_routes','ipv6_routes')),'label':'Маршруты '+interface})
    return {'ok':True,'checked':int(time.time()),'checks':checks,'tables':tables,'details':details,
            'note':'Только чтение. Содержит адреса, интерфейсы и правила; доступ администратора. Не доказывает доставку пакетов.'}
