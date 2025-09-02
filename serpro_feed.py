from pymisp import (MISPEvent, MISPSighting, MISPTag, MISPOrganisation, MISPObject)
from pymisp import MISPEvent, MISPObject, PyMISP, ExpandedPyMISP, MISPSharingGroup
import requests
import time
import datetime
import json
import urllib

url_serpro='https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt'


today=str(datetime.date.today())

r_serpro=requests.get(url_serpro)
url_misp = f"https://<MISP_IP_OR_HOSTNAME>"
key = 'MISP_AUTH_KEY'
misp_verifycert = False
misp = ExpandedPyMISP(url_misp, key, misp_verifycert)
event = MISPEvent()
event.info = "Serpro Feed - IP Reputation"
event.analysis = "2"
event.published = True
event.distribution = "4"
event.sharing_group_id = "1"
event.threat_level_id = "1"
for i in r_serpro.text.splitlines():
#  url_phishing=i.decode('utf-8').strip()
  event.add_attribute('ip-dst', str(i), comment="Malicious IP", disable_correlation=False, to_ids=True)
event.add_tag('tlp:amber+strict')
event.add_tag('malicious_ip')
event = misp.add_event(event)
