#!/usr/bin/env python3
"""Generate deterministic, synthetic HTTP PCAPs for the DICIB Wireshark CTF.

The files contain lab-only traffic. No external hosts are contacted and no real
credentials are used. Standard-library only: run with Python 3.

Usage:
    python tools/generate_wireshark_ctf.py

Creates:
    pcap/ALFA.pcap
    pcap/BRAVO.pcap
    pcap/CHARLY.pcap
    pcap/DELTA.pcap

The traffic deliberately uses TCP/80 so Wireshark recognizes HTTP immediately.
A useful starting filter for students is:
    http.request.uri contains "event"
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "pcap"
SERVER_IP = "10.10.10.80"
SERVER_MAC = bytes.fromhex("02 00 00 00 00 80")

TEAM_MAC = {
    "ALFA": bytes.fromhex("02 00 00 00 00 11"),
    "BRAVO": bytes.fromhex("02 00 00 00 00 12"),
    "CHARLY": bytes.fromhex("02 00 00 00 00 13"),
    "DELTA": bytes.fromhex("02 00 00 00 00 14"),
}
TEAM_IP_LAST = {"ALFA": 11, "BRAVO": 12, "CHARLY": 13, "DELTA": 14}

# The progression mirrors server/flags.js. Answers are synthetic training data.
def answer(team: str, n: int) -> str:
    values = [
        f"FLAG{{INICIO_{team}}}",
        f"FLAG{{{team}_BUSCA_EL_EVENTO}}",
        f"FLAG{{{team}_MIRA_LA_URI}}",
        f"FLAG{{{team}_FILTRA_HTTP}}",
        f"FLAG{{{team}_IDENTIFICA_EL_METODO}}",
        f"FLAG{{{team}_LOCALIZA_EL_HOST}}",
        f"FLAG{{{team}_IDENTIFICA_EL_ORIGEN}}",
        f"FLAG{{{team}_IDENTIFICA_EL_DESTINO}}",
        f"FLAG{{{team}_SIGUE_LA_CONEXION}}",
        f"FLAG{{{team}_BUSCA_EL_PARAMETRO}}",
        f"FLAG{{{team}_RECONSTRUYE_LA_PETICION}}",
        f"FLAG{{{team}_ENCUENTRA_EL_VALOR_OCULTO}}",
        f"FLAG{{{team}_SIGUE_LA_CADENA}}",
        "micorreoeswazowski@gmail.com",
        "JuniorTuPapa",
        f"FLAG{{{team}_REVISA_EL_CORREO}}",
        "Poyvi ha'e Colombia, ryvy Paraguái.",
        f"FLAG{{{team}_RECONSTRUYE_EL_MENSAJE}}",
        f"FLAG{{{team}_BUSCA_LA_IDENTIDAD}}",
        f"FLAG{{{team}_ENCUENTRA_EL_PERFIL}}",
        f"FLAG{{{team}_SIGUE_LA_PISTA_FINAL}}",
        f"FLAG{{{team}_UBICA_EL_USUARIO}}",
        f"FLAG{{{team}_BUSCA_INSTAGRAM}}",
        f"FLAG{{{team}_CONFIRMA_MIKEVARGAX}}",
        f"FLAG{{{team}_BUSCAR_INSTAGRAM_MIKEVARGAX}}",
    ]
    return values[n - 1]

CLUES = [
    "Inicio del expediente. La siguiente pista esta en otro evento.",
    "Busca el siguiente request con /event y conserva el mismo host.",
    "Observa la URI: el numero del evento coincide con el objetivo.",
    "Usa un filtro HTTP y evita el trafico de ruido.",
    "Metodo observado: GET. Sigue la misma conversacion TCP.",
    "Host de laboratorio: ctf.dicib.test. Ahora identifica el origen.",
    "Origen del cliente: 10.10.10.{ip}. Relaciona IP y equipo.",
    "Destino: 10.10.10.80:80. Continua siguiendo el flujo.",
    "Sigue la conexion TCP y revisa request y response.",
    "Parametro de interes: clue=event-{n}. Busca su valor.",
    "Reconstruye la peticion completa y lee el cuerpo de la respuesta.",
    "El valor oculto esta en X-CTF-Clue. No te quedes con el primer paquete.",
    "La cadena continua en /event/{n_plus}. Ordena los eventos.",
    "Pista administrativa: revisar el correo creado para el reto. Correo: micorreoeswazowski@gmail.com",
    "La credencial mostrada es ficticia y solo sirve para el laboratorio. Clave: JuniorTuPapa",
    "REVISAR EL CORREO. Busca el mensaje relacionado con Banco UENO.",
    "Dentro del correo hay una frase en guarani. Esa frase es la evidencia de esta etapa.",
    "Reconstruye el mensaje completo y conserva la frase encontrada.",
    "La siguiente pista pide identificar la identidad asociada al expediente.",
    "Busca el perfil mencionado por la evidencia anterior.",
    "Sigue la pista final y verifica que pertenece al mismo expediente.",
    "El usuario aparece en una cabecera de respuesta del evento.",
    "Ahora busca la referencia de Instagram.",
    "Confirma la cadena MIKEVARGAX dentro del tráfico del laboratorio.",
    "Objetivo final: buscar Instagram @MIKEVARGAX.",
]

NOISE = [
    "heartbeat node=LAB-01 status=ok",
    "telemetry cpu=41 memory=62",
    "dns query=updates.dicib.test answer=10.10.10.81",
    "healthcheck service=training status=200",
]


def ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, src_mac, dst_mac):
    version_ihl = 0x45
    total_len = 20 + 20 + len(payload)
    ident = (seq ^ ack) & 0xFFFF
    iphdr = struct.pack("!BBHHHBBH4s4s", version_ihl, 0, total_len, ident, 0, 64, 6, 0, ip_bytes(src_ip), ip_bytes(dst_ip))
    iphdr = struct.pack("!BBHHHBBH4s4s", version_ihl, 0, total_len, ident, 0, 64, 6, checksum(iphdr), ip_bytes(src_ip), ip_bytes(dst_ip))
    offset_flags = (5 << 12) | flags
    tcphdr = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 65535, 0, 0)
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, 6, len(tcphdr) + len(payload))
    tcphdr = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 65535, checksum(pseudo + tcphdr + payload), 0)
    frame = dst_mac + src_mac + struct.pack("!H", 0x0800) + iphdr + tcphdr + payload
    return frame


def record(ts_sec: int, ts_usec: int, frame: bytes) -> bytes:
    return struct.pack("!IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame


def http_pair(team: str, event_no: int, ts: int, client_ip: str, client_mac: bytes, noise_index: int):
    src_port = 40000 + event_no
    seq = 100000 + event_no * 1000
    ack = 500000 + event_no * 1000
    uri = f"/event/{team.lower()}/{event_no:02d}?clue=event-{event_no:02d}"
    req = (
        f"GET {uri} HTTP/1.1\r\n"
        f"Host: ctf.dicib.test\r\n"
        f"User-Agent: DICIB-Wireshark-Lab/1.0\r\n"
        f"Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    clue = CLUES[event_no - 1].format(ip=TEAM_IP_LAST[team], n=event_no, n_plus=min(event_no + 1, 25))
    body = (
        f"DICIB LAB EVENT {event_no:02d}\n"
        f"TEAM={team}\n"
        f"OBJECTIVE={team}-{event_no:02d}\n"
        f"CLUE={clue}\n"
        f"X-CTF-ANSWER={answer(team, event_no)}\n"
    ).encode()
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\nX-CTF-Clue: event-{event_no:02d}\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    frames = []
    frames.append(tcp_packet(client_ip, SERVER_IP, src_port, 80, seq, ack, 0x18, req, client_mac, SERVER_MAC))
    frames.append(tcp_packet(SERVER_IP, client_ip, 80, src_port, ack, seq + len(req), 0x18, resp, SERVER_MAC, client_mac))
    return frames


def generate(team: str):
    OUT.mkdir(parents=True, exist_ok=True)
    client_ip = f"10.10.10.{TEAM_IP_LAST[team]}"
    client_mac = TEAM_MAC[team]
    frames = []
    base = 1788000000 + list(TEAM_MAC).index(team) * 3600
    # Interleave harmless traffic so students must use filters and correlation.
    for n in range(1, 26):
        ts = base + n * 17
        if n % 3 == 0:
            noise = NOISE[(n + len(team)) % len(NOISE)].encode()
            frames.append(tcp_packet(SERVER_IP, client_ip, 80, 49000 + n, 700000 + n, 0, 0x18, noise, SERVER_MAC, client_mac))
        frames.extend(http_pair(team, n, ts, client_ip, client_mac, n))
    p = OUT / f"{team}.pcap"
    with p.open("wb") as f:
        # PCAP classic little-endian global header, Ethernet link type.
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        ts = base
        for i, frame in enumerate(frames):
            f.write(record(ts + i, (i * 137) % 1000000, frame))
    print(f"created {p} ({len(frames)} packets)")


if __name__ == "__main__":
    for team in ("ALFA", "BRAVO", "CHARLY", "DELTA"):
        generate(team)
