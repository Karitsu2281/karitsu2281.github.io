#!/bin/bash
# Script de analisis de logs para Proyecto 11
# Requiere: curl, python3 (para formatear JSON)

ES_HOST="${ES_HOST:-localhost:9200}"
INDEX="${INDEX:-proyecto11-logs-*}"
BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
NC="\033[0m"

echo -e "${BOLD}=============================================="
echo -e " ANALISIS DE COMPORTAMIENTOS NO DESEADOS"
echo -e " Proyecto 11 - Emulacion de Adversarios"
echo -e "==============================================${NC}"
echo ""

QUERY() {
  curl -s -X POST "${ES_HOST}/${INDEX}/_search" -H 'Content-Type: application/json' -d "$1" 2>/dev/null
}

COUNT() {
  QUERY "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('hits',{}).get('total',{}).get('value',d.get('hits',{}).get('total',0)))" 2>/dev/null || echo "N/A"
}

AGGS() {
  QUERY "$1" | python3 -m json.tool 2>/dev/null | grep -E '"(key|doc_count|value)"' | head -40
}

# ----------------------------------------------------
echo -e "${BOLD}1. PAQUETES BLOQUEADOS POR EL FIREWALL${NC}"
echo "   (Indica escaneo de puertos, intentos de conexion a servicios cerrados)"
echo "------------------------------------------------------------"
TOTAL_DROPS=$(COUNT '{"query":{"term":{"tags":"firewall_drop"}}}')
echo -e "   Total paquetes bloqueados: ${RED}${TOTAL_DROPS}${NC}"
echo ""
echo "   Top IPs atacantes:"
AGGS '{"size":0,"query":{"term":{"tags":"firewall_drop"}},"aggs":{"top_ips":{"terms":{"field":"src_ip.keyword","size":10}}}}'
echo ""
echo "   Distribucion por puerto destino:"
AGGS '{"size":0,"query":{"term":{"tags":"firewall_drop"}},"aggs":{"top_ports":{"terms":{"field":"dst_port.keyword","size":10}}}}'
echo ""
echo -e "   ${CYAN}Interpretacion:${NC} Muchos drops al puerto 22 = fuerza bruta SSH;"
echo "   puertos altos variados = escaneo de puertos; puerto 445 = intento SMB."

# ----------------------------------------------------
echo ""
echo -e "${BOLD}2. INTENTOS DE FUERZA BRUTA SSH${NC}"
echo "   (Comportamiento: Credential Access - MITRE T1110.001)"
echo "------------------------------------------------------------"
TOTAL_FAILS=$(COUNT '{"query":{"term":{"tags":"ssh_failed_attempt"}}}')
echo -e "   Total intentos fallidos: ${RED}${TOTAL_FAILS}${NC}"
echo ""
echo "   Top IPs atacantes:"
AGGS '{"size":0,"query":{"term":{"tags":"ssh_failed_attempt"}},"aggs":{"top_ips":{"terms":{"field":"src_ip.keyword","size":10}}}}'
echo ""
echo "   Usuarios objetivo del ataque:"
AGGS '{"size":0,"query":{"term":{"tags":"ssh_failed_attempt"}},"aggs":{"top_users":{"terms":{"field":"ssh_user.keyword","size":10}}}}'
echo ""
echo "   Intentos por minuto (patron temporal):"
AGGS '{"size":0,"query":{"term":{"tags":"ssh_failed_attempt"}},"aggs":{"over_time":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m"}}}}'
echo ""

# ----------------------------------------------------
echo -e "${BOLD}3. LOGINS SSH EXITOSOS${NC}"
echo "   (Comportamiento: Initial Access - MITRE T1078)"
echo "------------------------------------------------------------"
TOTAL_LOGINS=$(COUNT '{"query":{"term":{"tags":"ssh_login_success"}}}')
echo -e "   Total logins exitosos: ${RED}${TOTAL_LOGINS}${NC}"
echo ""
echo "   IPs con login exitoso:"
AGGS '{"size":0,"query":{"term":{"tags":"ssh_login_success"}},"aggs":{"top_ips":{"terms":{"field":"src_ip.keyword","size":10}}}}'
echo ""

# ----------------------------------------------------
echo -e "${BOLD}4. ALERTAS DE SURICATA IDS${NC}"
echo "   (Deteccion de exploits, escaneo, mov lateral, C2)"
echo "------------------------------------------------------------"
TOTAL_ALERTS=$(COUNT '{"query":{"term":{"tags":"suricata_alert"}}}')
echo -e "   Total alertas IDS: ${RED}${TOTAL_ALERTS}${NC}"
echo ""
echo "   Alertas por firma:"
AGGS '{"size":0,"query":{"term":{"tags":"suricata_alert"}},"aggs":{"top_sigs":{"terms":{"field":"alert_signature.keyword","size":20}}}}'
echo ""
echo "   Alertas por severidad:"
AGGS '{"size":0,"query":{"term":{"tags":"suricata_alert"}},"aggs":{"by_sev":{"terms":{"field":"alert_severity.keyword","size":5}}}}'
echo ""
echo "   Alertas de reglas personalizadas (PROYECTO11):"
AGGS '{"size":0,"query":{"bool":{"must":[{"term":{"tags":"suricata_alert"}},{"wildcard":{"alert_signature.keyword":"PROYECTO11*"}}]}},"aggs":{"custom_hits":{"terms":{"field":"alert_signature.keyword","size":20}}}}'
echo ""

# ----------------------------------------------------
echo -e "${BOLD}5. MOVIMIENTO LATERAL DETECTADO${NC}"
echo "   (SMB, WMI, RDP - MITRE T1021.002, T1047)"
echo "------------------------------------------------------------"
TOTAL_LATERAL=$(COUNT '{"query":{"term":{"tags":"lateral_movement"}}}')
echo -e "   Eventos de movimiento lateral: ${RED}${TOTAL_LATERAL}${NC}"
echo ""
echo "   Trafico SMB:"
AGGS '{"size":0,"query":{"term":{"tags":"suricata_smb_log"}},"aggs":{"smb_src":{"terms":{"field":"src_ip.keyword","size":10}}}}'
echo ""

# ----------------------------------------------------
echo -e "${BOLD}6. CORRELACION DE EVENTOS (analisis avanzado)${NC}"
echo "------------------------------------------------------------"
echo "   IPs con fuerza bruta Y login exitoso (compromiso confirmado):"
QUERY '{
  "size": 0,
  "query": {"bool": {"must": [{"term": {"tags": "ssh_failed_attempt"}}]}},
  "aggs": {
    "attackers": {
      "terms": {"field": "src_ip.keyword", "size": 10},
      "aggs": {
        "also_succeeded": {
          "filter": {"term": {"tags": "ssh_login_success"}},
          "aggs": {"success_from": {"terms": {"field": "src_ip.keyword", "size": 5}}}
        }
      }
    }
  }
}' | python3 -c "
import sys,json
d=json.load(sys.stdin)
for b in d.get('aggregations',{}).get('attackers',{}).get('buckets',[]):
    succ=b.get('also_succeeded',{}).get('doc_count',0)
    if succ>0:
        print(f'  [!] {b[\"key\"]}: {b[\"doc_count\"]} fallos, {succ} exitos -> COMPROMETIDA')
"
echo ""

# ----------------------------------------------------
echo -e "${BOLD}=============================================="
echo -e " RESUMEN CUANTITATIVO"
echo -e "==============================================${NC}"
echo ""
printf "  %-40s %s\n" "Metrica" "Valor"
echo "  ------------------------------------------------------------------"
printf "  %-40s %s\n" "Paquetes bloqueados por firewall" "${TOTAL_DROPS}"
printf "  %-40s %s\n" "Intentos fallidos SSH (fuerza bruta)" "${TOTAL_FAILS}"
printf "  %-40s %s\n" "Logins SSH exitosos" "${TOTAL_LOGINS}"
printf "  %-40s %s\n" "Alertas Suricata IDS" "${TOTAL_ALERTS}"
printf "  %-40s %s\n" "Eventos de movimiento lateral" "${TOTAL_LATERAL}"
echo ""

# ----------------------------------------------------
echo -e "${BOLD}=============================================="
echo -e " CLASIFICACION MITRE ATT&CK DETECTADA"
echo -e "==============================================${NC}"
echo ""
for tag in "MITRE_T1046" "MITRE_T1110.001" "MITRE_T1078" "MITRE_T1021.002" "MITRE_T1047" "MITRE_T1203"; do
  MITRE_COUNT=$(COUNT "{\"query\":{\"term\":{\"tags\":\"${tag}\"}}}")
  if [ "${MITRE_COUNT}" != "0" ] && [ "${MITRE_COUNT}" != "N/A" ]; then
    case $tag in
      MITRE_T1046) DESC="Network Service Discovery (escaneo)" ;;
      MITRE_T1110.001) DESC="Brute Force: Password Guessing" ;;
      MITRE_T1078) DESC="Valid Accounts (logins exitosos)" ;;
      MITRE_T1021.002) DESC="Remote Services: SMB (mov lateral)" ;;
      MITRE_T1047) DESC="WMI (mov lateral)" ;;
      MITRE_T1203) DESC="Exploitation for Client Execution" ;;
      *) DESC="Tecnica MITRE detectada" ;;
    esac
    printf "  %-15s %-8s %s\n" "${tag}" "${MITRE_COUNT}" "eventos - ${DESC}"
  fi
done

echo ""
echo -e "${GREEN}[+] Analisis completado. Abre http://localhost:5601 para visualizaciones interactivas.${NC}"
echo ""
echo "Dashboard Kibana recomendado:"
echo "  - Stack Management > Saved Objects > Import > kibana_dashboard.ndjson"
echo "  - O crea visualizaciones manualmente: tipo 'Vertical Bar' para cada metrica"
