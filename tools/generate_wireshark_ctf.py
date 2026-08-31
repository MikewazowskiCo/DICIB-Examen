#!/usr/bin/env python3
"""Generador de PCAP sintético para el CTF de Wireshark DICIB.

Solo genera tráfico de laboratorio. No contacta hosts externos y no usa
credenciales reales. Los cuatro PCAP tienen la misma dificultad.

Uso:
  python tools/generate_wireshark_ctf.py

Salida:
  public/pcap/ALFA.pcap, BRAVO.pcap, CHARLY.pcap, DELTA.pcap

Diseño: tráfico constante durante 120 minutos, con 25 eventos útiles
progresivamente distribuidos y numerosos señuelos en español.
"""
from __future__ import annotations
import base64, struct
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "public" / "pcap"
SERVER_IP = "10.10.10.80"
SERVER_MAC = bytes.fromhex("02 00 00 00 00 80")
TEAMS = {
    "ALFA": (11, "02 00 00 00 00 11"),
    "BRAVO": (12, "02 00 00 00 00 12"),
    "CHARLY": (13, "02 00 00 00 00 13"),
    "DELTA": (14, "02 00 00 00 00 14"),
}

EVENT_MINUTES = [4, 8, 12, 16, 21, 25, 30, 35, 39, 44, 49, 54, 59,
                 64, 69, 74, 79, 84, 89, 94, 99, 104, 109, 114, 118]

FALSE_FLAGS = [
    "FLAG{ACCESO_AUTORIZADO_LAB}", "FLAG{EVENTO_NO_VALIDADO}",
    "FLAG{PISTA_TEMPORAL_FALSA}", "FLAG{REVISA_EL_HOST}",
    "FLAG{CONEXION_DE_PRUEBA}", "FLAG{EVIDENCIA_DESCARTADA}",
    "FLAG{RUIDO_DEL_LABORATORIO}", "FLAG{NO_ES_LA_RESPUESTA}",
    "FLAG{PAQUETE_SEÑUELO}", "FLAG{IDENTIDAD_NO_CONFIRMADA}",
    "FLAG{EVENTO_SECUNDARIO}", "FLAG{DATO_DE_TELEMETRIA}",
    "FLAG{BUSQUEDA_INCOMPLETA}", "FLAG{PISTA_DE_RED_FALSA}",
    "FLAG{CORRELACION_INCORRECTA}", "FLAG{MENSAJE_DE_PRUEBA}",
    "FLAG{PERFIL_NO_VALIDADO}", "FLAG{RUTA_DESCARTADA}",
    "FLAG{REFERENCIA_FICTICIA}", "FLAG{ULTIMO_EVENTO_FALSO}",
]


def answer(team, n):
    vals = [
        f"FLAG{{INICIO_{team}}}", f"FLAG{{{team}_BUSCA_EL_EVENTO}}", f"FLAG{{{team}_MIRA_LA_URI}}",
        f"FLAG{{{team}_FILTRA_HTTP}}", f"FLAG{{{team}_IDENTIFICA_EL_METODO}}", f"FLAG{{{team}_LOCALIZA_EL_HOST}}",
        f"FLAG{{{team}_IDENTIFICA_EL_ORIGEN}}", f"FLAG{{{team}_IDENTIFICA_EL_DESTINO}}", f"FLAG{{{team}_SIGUE_LA_CONEXION}}",
        f"FLAG{{{team}_BUSCA_EL_PARAMETRO}}", f"FLAG{{{team}_RECONSTRUYE_LA_PETICION}}", f"FLAG{{{team}_ENCUENTRA_EL_VALOR_OCULTO}}",
        f"FLAG{{{team}_SIGUE_LA_CADENA}}", "micorreoeswazowski@gmail.com", "JuniorTuPapa", f"FLAG{{{team}_REVISA_EL_CORREO}}",
        "Poyvi ha'e Colombia, ryvy Paraguái.", f"FLAG{{{team}_RECONSTRUYE_EL_MENSAJE}}", f"FLAG{{{team}_BUSCA_LA_IDENTIDAD}}",
        f"FLAG{{{team}_ENCUENTRA_EL_PERFIL}}", f"FLAG{{{team}_SIGUE_LA_PISTA_FINAL}}", f"FLAG{{{team}_UBICA_EL_USUARIO}}",
        f"FLAG{{{team}_BUSCA_INSTAGRAM}}", f"FLAG{{{team}_CONFIRMA_MIKEVARGAX}}", "HACK THE WORLD"
    ]
    return vals[n - 1]


CLUES = [
    "Encuentra el valor codificado en Base64 y decodificalo.",
    "La respuesta esta en hexadecimal. Convierte los bytes a texto.",
    "La pista esta URL-encoded en X-CTF-Evidence. Usa Decode/URL.",
    "Observa el metodo HTTP del request y relaciona el evento con el objetivo.",
    "Busca X-CTF-Evidence y aplica ROT13 al valor.",
    "Identifica el Host y usa la evidencia del mismo flujo TCP.",
    "Compara la IP origen con la IP asignada a tu equipo.",
    "Compara la IP destino con el servidor del laboratorio.",
    "Usa Follow TCP Stream para reconstruir la conversacion.",
    "Busca clue=event y lee el parametro asociado.",
    "Lee la respuesta completa; la evidencia esta separada del ruido.",
    "El valor esta dividido en dos cabeceras X-CTF-Part-A y X-CTF-Part-B; unelas.",
    "Ordena los eventos por numero antes de continuar.",
    "REVISAR EL CORREO creado para el reto. Identifica el correo en la evidencia.",
    "La clave es ficticia y esta en el evento de credenciales del laboratorio.",
    "REVISAR EL CORREO. Busca el mensaje relacionado con Banco UENO.",
    "Dentro del correo esta la frase en guarani; conserva exactamente sus caracteres.",
    "Reconstruye el mensaje y verifica la evidencia anterior.",
    "Identifica la identidad asociada al expediente.",
    "Busca el perfil mencionado por la evidencia.",
    "Sigue la pista final y verifica que pertenece al mismo expediente.",
    "El usuario aparece en una cabecera de respuesta.",
    "Busca la referencia de Instagram.",
    "Confirma la cadena MIKEVARGAX.",
    "Objetivo final: busca en Instagram el perfil @mikevargax y encuentra la frase de su biografia: HACK THE WORLD."
]

NOISE = [
    "heartbeat nodo=LAB-01 estado=ok", "telemetria cpu=41 memoria=62",
    "consulta dns=actualizaciones.dicib.test respuesta=10.10.10.81",
    "healthcheck servicio=entrenamiento estado=200", "registro=normal prioridad=baja",
    "sesion=simulada resultado=correcto",
]


def ip_bytes(ip):
    return bytes(int(x) for x in ip.split('.'))


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data)//2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def tcp_packet(src_ip, dst_ip, sport, dport, seq, ack, flags, payload, src_mac, dst_mac):
    total = 40 + len(payload)
    ident = (seq ^ ack) & 0xffff
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, ident, 0, 64, 6, 0,
                      ip_bytes(src_ip), ip_bytes(dst_ip))
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, ident, 0, 64, 6,
                      checksum(iph), ip_bytes(src_ip), ip_bytes(dst_ip))
    off = (5 << 12) | flags
    th = struct.pack('!HHIIHHHH', sport, dport, seq, ack, off, 65535, 0, 0)
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack('!BBH', 0, 6, len(th) + len(payload))
    th = struct.pack('!HHIIHHHH', sport, dport, seq, ack, off, 65535,
                     checksum(pseudo + th + payload), 0)
    return dst_mac + src_mac + struct.pack('!H', 0x0800) + iph + th + payload


def evidence(team, n):
    a = answer(team, n).encode('utf-8')
    if n == 1:
        return 'BASE64', base64.b64encode(a).decode(), None
    if n == 2:
        return 'HEX', a.hex(), None
    if n == 3:
        return 'URL', ''.join('%%%02X' % b if b in b'{} ' else chr(b) for b in a), None
    if n == 5:
        import codecs
        return 'ROT13', codecs.encode(a.decode(), 'rot_13'), None
    if n == 12:
        mid = len(a) // 2
        return 'SPLIT', a[:mid].decode(), a[mid:].decode()
    return 'PLAIN', a.decode('utf-8'), None


def pair(team, n, client_ip, client_mac):
    sport = 40000 + n
    seq = 100000 + n * 1000
    ack = 500000 + n * 1000
    uri = f'/event/{team.lower()}/{n:02d}?clue=event-{n:02d}'
    req = (f'GET {uri} HTTP/1.1\r\nHost: ctf.dicib.test\r\n'
           f'User-Agent: DICIB-Wireshark-Lab/1.0\r\nAccept: */*\r\n'
           f'Connection: close\r\n\r\n').encode()
    mode, ev, ev2 = evidence(team, n)
    body = (f'DICIB LAB EVENT {n:02d}\nTEAM={team}\nOBJECTIVE={team}-{n:02d}\n'
            f'CLUE={CLUES[n-1]}\nENCODING={mode}\nEVIDENCE={ev}')
    if ev2 is not None:
        body += f'\nEVIDENCE-2={ev2}'
    body += '\n'
    body = body.encode('utf-8')
    headers = (f'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n'
               f'Content-Length: {len(body)}\r\nX-CTF-Clue: event-{n:02d}\r\n')
    if n == 12:
        headers += f'X-CTF-Part-A: {ev}\r\nX-CTF-Part-B: {ev2}\r\n'
    if n == 14:
        headers += 'X-CTF-Review: REVISAR-CORREO\r\n'
    if n == 16:
        headers += 'X-CTF-Review: BANCO-UENO\r\n'
    if n == 17:
        headers += 'X-CTF-Language: GUARANI\r\n'
    resp = (headers + 'Connection: close\r\n\r\n').encode() + body
    return [
        tcp_packet(client_ip, SERVER_IP, sport, 80, seq, ack, 0x18, req, client_mac, SERVER_MAC),
        tcp_packet(SERVER_IP, client_ip, 80, sport, ack, seq + len(req), 0x18, resp, SERVER_MAC, client_mac)
    ]


def noise_packet(team, idx, client_ip, client_mac, text):
    payload = text.encode('utf-8')
    return tcp_packet(SERVER_IP, client_ip, 80, 49000 + idx, 700000 + idx, 0,
                      0x18, payload, SERVER_MAC, client_mac)


def false_flag_packet(team, idx, client_ip, client_mac):
    false = FALSE_FLAGS[(idx + len(team)) % len(FALSE_FLAGS)]
    payload = (f'LAB SEÑUELO\nTIPO=FALSA\nEVIDENCIA={false}\n'
               f'NOTA=No corresponde al objetivo actual.\n').encode('utf-8')
    return tcp_packet(SERVER_IP, client_ip, 80, 51000 + idx, 800000 + idx, 0,
                      0x18, payload, SERVER_MAC, client_mac)


def generate(team):
    last, mac_hex = TEAMS[team]
    client_ip = f'10.10.10.{last}'
    client_mac = bytes.fromhex(mac_hex)
    frames = []
    base = 1788000000 + list(TEAMS).index(team) * 3600

    event_by_minute = dict(zip(EVENT_MINUTES, range(1, 26)))
    total_seconds = 120 * 60
    for sec in range(0, total_seconds, 20):
        minute = sec // 60
        second = sec % 60
        if minute in event_by_minute and second < 20:
            n = event_by_minute[minute]
            frames.extend(pair(team, n, client_ip, client_mac))
        else:
            idx = sec // 20
            if idx % 3 == 0:
                frames.append(false_flag_packet(team, idx, client_ip, client_mac))
            else:
                frames.append(noise_packet(team, idx, client_ip, client_mac,
                                           NOISE[idx % len(NOISE)]))

    OUT.mkdir(parents=True, exist_ok=True)
    p = OUT / f'{team}.pcap'
    with p.open('wb') as f:
        f.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            ts = base + i * 20
            f.write(struct.pack('<IIII', ts, (i * 137) % 1000000,
                                len(frame), len(frame)) + frame)
    print(f'created {p} ({len(frames)} packets; 120 min synthetic timeline)')


if __name__ == '__main__':
    for team in TEAMS:
        generate(team)
