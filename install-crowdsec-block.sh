#!/bin/sh
# ==========================================================================
# Instalador de crowdsec-block para routers ASUS con Asuswrt-Merlin
#
#   curl -fsSL https://raw.githubusercontent.com/germanyague/blocklist/main/install-crowdsec-block.sh | sh
#
# Que hace:
#   1. Escribe /jffs/scripts/crowdsec-block
#   2. Registra el cron (cada 30 min) y lo deja anotado en services-start
#      para que sobreviva a los reinicios
#   3. Anade la llamada en firewall-start para que se reaplique cuando el
#      firewall se reinicia
#   4. Hace la primera carga
#
# Para que sirve: descarta a nivel de paquete las IPs que CrowdSec ha baneado
# en el NAS, publicadas en blocklist.txt. Es independiente de Skynet, cuya
# whitelist de rangos CDN incluye Azure y Google Cloud enteros y por tanto
# anula esos bans.
#
# Idempotente: se puede ejecutar las veces que haga falta.
# Para desinstalar:  sh /jffs/scripts/crowdsec-block unload
# ==========================================================================

set -e

DEST=/jffs/scripts/crowdsec-block
SS=/jffs/scripts/services-start
FS=/jffs/scripts/firewall-start
CRU='cru a CrowdSecBlock "*/30 * * * * sh /jffs/scripts/crowdsec-block"'

echo "[i] Comprobando entorno…"
[ -d /jffs/scripts ] || { echo "[!] No existe /jffs/scripts. ¿Esta activado JFFS custom scripts en el router?"; exit 1; }
command -v ipset    >/dev/null 2>&1 || { echo "[!] Falta ipset";    exit 1; }
command -v iptables >/dev/null 2>&1 || { echo "[!] Falta iptables"; exit 1; }
echo "[i] OK: $(uname -a)"

echo "[i] Escribiendo $DEST…"
cat > "$DEST" <<'FIN_DEL_SCRIPT'
#!/bin/sh
# crowdsec-block — aplica la blocklist de CrowdSec en un ipset propio.
#
# Por que existe: en Skynet la whitelist es absoluta (regla con
# "! match-set Skynet-MasterWL src"), y sus entradas CDN whitelistean
# rangos enteros de Azure y Google Cloud, que es de donde viene el 100%
# de los ataques. Este set va en posicion 1 de raw PREROUTING, antes de
# la comprobacion de whitelist de Skynet, para que los bans de CrowdSec
# ganen.
#
# Solo filtra trafico ENTRANTE (src). No puede romper nada saliente.
#
# El set CrowdSec-Allow protege lo que nunca debe dropearse: rangos
# privados/reservados y los rangos de Cloudflare (por donde entra el
# trafico de los dominios proxied). La regla exige NO estar en Allow Y
# SI estar en CrowdSec, igual que hace Skynet con su MasterWL.
#
# Uso: crowdsec-block          -> actualiza el set y asegura la regla
#      crowdsec-block status   -> estado y contadores
#      crowdsec-block unload   -> quita regla y sets, sin rastro

URL="https://raw.githubusercontent.com/germanyague/blocklist/refs/heads/main/blocklist.txt"
SET="CrowdSec"
ALLOW="CrowdSec-Allow"
TMPSET="CrowdSec-new"
TMPFILE="/tmp/crowdsec-block.dl"
LOG="/tmp/mnt/ASUS/skynet/crowdsec-block.log"
MYIP="90.173.34.4"
MINIPS=100          # si la descarga trae menos, se aborta sin tocar el set

log() { echo "$(date '+%b %d %H:%M:%S') $*" >> "$LOG"; }

Rule_Exists() {
	iptables -t raw -C PREROUTING -m set ! --match-set "$ALLOW" src \
		-m set --match-set "$SET" src -j DROP 2>/dev/null
}

Build_Allow() {
	ipset -q create "$ALLOW" hash:net hashsize 128 maxelem 1024
	ipset flush "$ALLOW"
	{
		# Privadas y reservadas. 192.168.0.1 (el propio router) aparece en
		# la blocklist por el NAT hairpin del NAS: dropearlo seria fatal.
		for n in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 \
			169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 \
			224.0.0.0/4 240.0.0.0/4; do
			echo "add $ALLOW $n"
		done
		echo "add $ALLOW $MYIP"
		# Cloudflare: los dominios proxied reciben el trafico DESDE estas
		# IPs. Si alguna cae en la blocklist y la dropeamos, esas webs se
		# caen. Ya hubo una (198.41.144.252).
		curl -fsSL --retry 3 --max-time 20 https://www.cloudflare.com/ips-v4 \
			| grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' \
			| sed "s|^|add $ALLOW |"
	} | ipset restore -!
	log "allow-list reconstruida: $(ipset -L "$ALLOW" | sed -n 's/^Number of entries: //p') entradas"
}

case "$1" in
	unload)
		while Rule_Exists; do
			iptables -t raw -D PREROUTING -m set ! --match-set "$ALLOW" src \
				-m set --match-set "$SET" src -j DROP
		done
		ipset destroy "$TMPSET" 2>/dev/null
		ipset destroy "$SET" 2>/dev/null
		ipset destroy "$ALLOW" 2>/dev/null
		log "descargado: regla y sets eliminados"
		echo "[i] crowdsec-block descargado"
		exit 0
	;;
	status)
		echo "[i] IPs bloqueadas : $(ipset -L "$SET" 2>/dev/null | sed -n 's/^Number of entries: //p')"
		echo "[i] Exclusiones    : $(ipset -L "$ALLOW" 2>/dev/null | sed -n 's/^Number of entries: //p')"
		echo "[i] Regla activa   : $(Rule_Exists && echo si || echo NO)"
		iptables -t raw -L PREROUTING -n -v 2>/dev/null \
			| awk -v s="$SET" '$0 ~ "match-set "s" src" {print "[i] Bloqueado      : "$1" paquetes, "$2" bytes"}'
		echo "[i] Log:"
		tail -6 "$LOG" 2>/dev/null
		exit 0
	;;
esac

# 1) los sets deben existir siempre, aunque la descarga falle
ipset -q create "$SET" hash:ip hashsize 8192 maxelem 131072
Build_Allow

# 2) la regla va en posicion 1, por delante de las de Skynet
if ! Rule_Exists; then
	iptables -t raw -I PREROUTING 1 -m set ! --match-set "$ALLOW" src \
		-m set --match-set "$SET" src -j DROP
	log "regla DROP insertada en posicion 1"
fi

# 3) descargar
if ! curl -fsSL --retry 3 --max-time 45 "$URL" -o "$TMPFILE"; then
	log "ERROR descarga fallida, se conserva el contenido anterior del set"
	exit 1
fi

# 4) no vaciar el set por una descarga truncada o una pagina de error
count=$(grep -cE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$TMPFILE")
if [ "$count" -lt "$MINIPS" ]; then
	log "ERROR solo $count IPs validas (minimo $MINIPS), se aborta sin tocar el set"
	rm -f "$TMPFILE"
	exit 1
fi

# 5) cargar en un set temporal y hacer swap atomico: el set nunca queda a medias
ipset destroy "$TMPSET" 2>/dev/null
ipset create "$TMPSET" hash:ip hashsize 8192 maxelem 131072
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$TMPFILE" \
	| sed "s/^/add $TMPSET /" \
	| ipset restore -!
ipset swap "$TMPSET" "$SET"
ipset destroy "$TMPSET"
rm -f "$TMPFILE"

log "OK $count IPs cargadas"
FIN_DEL_SCRIPT
chmod 755 "$DEST"
sh -n "$DEST" || { echo "[!] El script escrito tiene errores de sintaxis"; exit 1; }
echo "[i] Escrito y validado."

# ── Cron, ahora y en cada arranque ────────────────────────────────────────
cru d CrowdSecBlock 2>/dev/null || true
cru a CrowdSecBlock "*/30 * * * * sh /jffs/scripts/crowdsec-block"

[ -f "$SS" ] || { printf '#!/bin/sh\n' > "$SS"; chmod 755 "$SS"; }
if grep -q "CrowdSecBlock" "$SS"; then
	echo "[i] services-start ya lo tenia."
else
	echo "$CRU" >> "$SS"
	echo "[i] services-start actualizado."
fi

[ -f "$FS" ] || { printf '#!/bin/sh\n' > "$FS"; chmod 755 "$FS"; }
if grep -q "crowdsec-block" "$FS"; then
	echo "[i] firewall-start ya lo tenia."
else
	echo "sh /jffs/scripts/crowdsec-block # CrowdSec" >> "$FS"
	echo "[i] firewall-start actualizado."
fi

echo "[i] Primera carga…"
sh "$DEST"
echo
sh "$DEST" status
echo
echo "[i] Listo. El cron refresca la lista cada 30 minutos."
