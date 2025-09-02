#!/bin/bash
key="<MISP_AUTH_KEY>"
misp_url="https://<MISP_IP_OR_HOSTNAME>"
rule_file_apt="/etc/suricata/rules/misp_apt.rules"
rule_file_serpro="/etc/suricata/rules/misp_serpro.rules"
rule_file_phishing="/etc/suricata/rules/misp_phishing.rules"
#curl -H "Authorization: $key" "$misp_url/attributes/restSearch/download/returnFormat:suricata/type:ip-src||ip-dst" -o /etc/suricata/rules/misp.rules
curl -H "Authorization: $key" -k "$misp_url/attributes/restSearch/download/returnFormat:suricata/tags:malicious_ip/type:ip-src||ip-dst||domain||url" -o $rule_file_serpro
curl -H "Authorization: $key" -k "$misp_url/attributes/restSearch/download/returnFormat:suricata/tags:APT/type:ip-src||ip-dst||domain||url" -o $rule_file_apt
curl -H "Authorization: $key" -k "$misp_url/attributes/restSearch/download/returnFormat:suricata/tags:openphish/type:ip-src||ip-dst||domain||url" -o $rule_file_phishing
sed -i s/'trojan-activity'/'apt-activity'/g $rule_file_apt
sed -i s/'trojan-activity'/'phishing'/g $rule_file_phishing
sed -i s/'trojan-activity'/'malicious-ip'/g $rule_file_serpro
systemctl restart suricata
