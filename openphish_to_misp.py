from pymisp import (MISPEvent, MISPSighting, MISPTag, MISPOrganisation, MISPObject)
from pymisp import MISPEvent, MISPObject, PyMISP, ExpandedPyMISP, MISPSharingGroup
import requests
import time
import datetime
import json
import urllib

url_openphish='https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'


today=str(datetime.date.today())

r_phishing=requests.get(url_openphish)
url_misp = f"https://<MISP_IP_OR_HOSTNAME>"
key = 'MISP_AUTH_KEY'
misp_verifycert = False
misp = ExpandedPyMISP(url_misp, key, misp_verifycert)
event = MISPEvent()
event.info = "Openphish daily report"
event.analysis = "2"
event.published = True
event.distribution = "4"
event.sharing_group_id = "1"
event.threat_level_id = "1"
for i in r_phishing.text.splitlines():
#  url_phishing=i.decode('utf-8').strip()
  url_phishing=i
  print(url_phishing)
  event.add_attribute('url', str(url_phishing), comment="Phishing URL", disable_correlation=False, to_ids=True)
event.add_tag('tlp:amber+strict')
event.add_tag('openphish')
event.add_tag('enisa:nefarious-activity-abuse="phishing-attacks"')
event = misp.add_event(event)
