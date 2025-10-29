from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
import json
from datetime import datetime

# Configuração da conexão MISP
misp_url = '<MISP_URL>'
misp_key = '<MISP_KEY>'
misp_verifycert = True

# Inicializar conexão com o MISP
try:
    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
except Exception as e:
    print(f"Erro ao conectar com MISP: {e}")
    exit()

# Criar um novo evento
event = MISPEvent()
event.info = "Honeypot alerts"
event.distribution = 0
event.threat_level_id = 2  # Médio
event.analysis = 1  # Em andamento
event.published = True
event.add_tag('tlp:amber+strict')
event.add_tag('honeypot_ptb_cert')
event = misp.add_event(event)
# Dados fornecidos
data = {
    "TableName": "Results",
    "Columns": [
        {"ColumnName": "EventTime", "DataType": "DateTime"},
        {"ColumnName": "DstIP", "DataType": "String"},
        {"ColumnName": "SrcIP", "DataType": "String"},
        {"ColumnName": "Action", "DataType": "String"},
        {"ColumnName": "PolicyName", "DataType": "String"},
        {"ColumnName": "PolicyID", "DataType": "String"},
        {"ColumnName": "SrcPort", "DataType": "Int32"},
        {"ColumnName": "DstPort", "DataType": "Int32"},
        {"ColumnName": "Service", "DataType": "String"},
        {"ColumnName": "SrcCountry", "DataType": "String"},
        {"ColumnName": "DevName", "DataType": "String"}
    ],
    "Rows": [
        # ... (todos os dados fornecidos)
        ["2025-09-15T13:08:00.219Z","164.85.42.1","91.191.209.198","server-rst","outside x honeypot","10017",57834,12200,"tcp/12200","Bulgaria","FW813CIPD"],
        # ... (restante dos dados)
    ]
}

# Mapear colunas para índices
column_map = {col['ColumnName']: idx for idx, col in enumerate(data['Columns'])}

# Contadores para estatísticas
total_objects = 0
successful_objects = 0
failed_objects = 0

# Processar cada linha de dados
for row in data['Rows']:
    try:
        # Extrair dados da linha
        event_time = row[column_map['EventTime']]
        src_ip = row[column_map['SrcIP']]
        dst_ip = row[column_map['DstIP']]
        dst_port = row[column_map['DstPort']]
        src_port = row[column_map['SrcPort']]
        action = row[column_map['Action']]
        service = row[column_map['Service']]
        src_country = row[column_map['SrcCountry']]
        policy_name = row[column_map['PolicyName']]
        
        # Pular linhas com valores nulos
        if src_port is None or dst_port is None:
            continue
            
        # Criar objeto IP-Port
        ip_port_obj = MISPObject('ip-port')
        
        # Adicionar atributos obrigatórios
        ip_port_obj.add_attribute('ip', value=src_ip)
        ip_port_obj.add_attribute('dst-port', value=str(dst_port))
        
        # Adicionar atributos opcionais
        ip_port_obj.add_attribute('src-port', value=str(src_port))
        ip_port_obj.add_attribute('protocol', value='TCP')  # Assumindo TCP baseado nos dados
        
        # Adicionar informações contextuais
        comment = f"Ação: {action} | Serviço: {service} | País: {src_country} | Política: {policy_name}"
        ip_port_obj.comment = comment
        
        # Adicionar timestamps
        ip_port_obj.add_attribute('first-seen', value=event_time)
        ip_port_obj.add_attribute('last-seen', value=event_time)
        
        # Adicionar tags baseadas na ação
        if action in ['deny', 'server-rst', 'timeout']:
            ip_port_obj.add_tag('network:scan')
            ip_port_obj.add_tag('intrusion:attempt')
        
        if 'honeypot' in policy_name.lower():
            ip_port_obj.add_tag('decoy:honeypot')
        
        # Adicionar objeto ao evento
        result = misp.add_object(event.id, ip_port_obj)
        successful_objects += 1
        total_objects += 1
        
        print(f"✓ Objeto criado para {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
    except Exception as e:
        failed_objects += 1
        total_objects += 1
        print(f"✗ Erro ao processar linha: {e}")
        continue

# Adicionar informações de resumo ao evento
summary_comment = f"""
Resumo da importação:
- Total de objetos processados: {total_objects}
- Objetos criados com sucesso: {successful_objects}
- Objetos com erro: {failed_objects}
- Período: {data['Rows'][0][0]} até {data['Rows'][-1][0]}
- Fonte: Logs de firewall honeypot
"""

event.comment = summary_comment
misp.update_event(event)

print(f"\n=== PROCESSAMENTO CONCLUÍDO ===")
print(f"Evento MISP: {misp_url}/events/view/{event.id}")
print(f"Total de objetos processados: {total_objects}")
print(f"Objetos criados com sucesso: {successful_objects}")
print(f"Objetos com erro: {failed_objects}")

# Exemplo de consulta para verificar os objetos criados
try:
    print("\n=== AMOSTRA DOS OBJETOS CRIADOS ===")
    event_complete = misp.get_event(event.id)
    
    ip_ports = [obj for obj in event_complete.objects if obj.name == 'ip-port']
    
    for i, obj in enumerate(ip_ports[:5]):  # Mostrar apenas os 5 primeiros
        ip = obj.get_attributes_by_relation('ip')[0].value
        dst_port = obj.get_attributes_by_relation('dst-port')[0].value
        src_port = obj.get_attributes_by_relation('src-port')[0].value if obj.get_attributes_by_relation('src-port') else 'N/A'
        
        print(f"{i+1}. {ip}:{src_port} -> Porta {dst_port}")
        
    print(f"\n... e mais {len(ip_ports) - 5} objetos")
    
except Exception as e:
    print(f"Erro na consulta: {e}")
