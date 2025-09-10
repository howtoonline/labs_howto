from pymisp import (MISPEvent, MISPSighting, MISPTag, MISPOrganisation, MISPObject, MISPGalaxy)
from pymisp import MISPEvent, MISPObject, PyMISP, ExpandedPyMISP, MISPSharingGroup, MISPGalaxy
import requests
import time
import datetime
import json
today=str(datetime.date.today())
cont = 1
while cont < 50:
    print('page:', cont)
    alien_url=f"https://otx.alienvault.com/api/v1/pulses/subscribed?page={cont}"
    alien_key = "<OTX-API_KEY>"
    alien_header = {'X-OTX-API-KEY': alien_key}
    alien_r=requests.request(method='GET', url=f"{alien_url}", headers=alien_header)
    misp_url = "https://<MISP_HOST>"
    key = '<MISP_KEY>'
    misp_verifycert = False
    pulses=json.loads(alien_r.text)
    for p in pulses['results']:
        name = p['name']
        desc = p['description']
        adv = p['adversary']
        created = p['created']
        date = created.split('T')[0]
        print(date, today) 
        misp = ExpandedPyMISP(misp_url, key, misp_verifycert)
        event = MISPEvent()
        event.info = f"{name}"
        event.analysis = "2"
        event.published = True
        event.distribution = "4" 
        event.sharing_group_id = "1" #level HIGH
        event.threat_level_id = "1" #level HIGH
        event.add_tag('tlp:clear')
        if not adv in '': 
            event.add_tag('Adversary:'+adv+'')
        event.add_attribute('datetime', str(created), comment='Created', disable_correlation=True)
        for i in p['indicators']:
            ioc = i['indicator']
            ioc_type = i['type']
            if ioc_type in 'FileHash-MD5':
                ioc_type = 'md5'
            if ioc_type in 'FileHash-SHA1':
                ioc_type = 'sha1'
            if ioc_type in 'FileHash-SHA256':
                ioc_type = 'sha256'
            if ioc_type in 'FileHash-SHA512':
                ioc_type = 'sha512'
            if ioc_type in 'BitcoinAddress':
                ioc_type = 'btc'
            if ioc_type in 'URL':
                ioc_type = 'url' 
            if ioc_type in 'CVE':
                ioc_type = 'vulnerability' 
            if ioc_type in 'IPv4':
                ioc_type = 'ip-src'
            if ioc_type in 'YARA':
                ioc_type = 'comment' 
            if ioc_type in 'SSLCertFingerprint':
                ioc_type = 'comment'
            event.add_attribute(''+ioc_type+'', str(ioc), disable_correlaction=False)
        for t in p['tags']:
            event.add_tag(''+t+'')
        for c in p['targeted_countries']:
            event.add_attribute('comment', str(c), comment='Targeted Country', disable_correlation=True)
            print(c)
        for d in p['industries']:
            event.add_tag('industry:'+d+'') 
        for m in p['malware_families']:
            event.add_tag('malware_family:'+m+'')
        for e in p['attack_ids']:
            event.add_tag(''+e+'')
        for r in p['references']:
            event.add_attribute('comment', str(r), comment='Reference', disable_correlation=True)
#publicando o evento no MISP
        if 'Brazil' in p['targeted_countries']:
            event.add_tag('Targeted_country:BRAZIL')   
        event = misp.add_event(event)
        cont = cont + 1