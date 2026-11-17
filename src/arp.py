
"""Descobre dispositivos via ARP na rede isolada do laboratório Docker."""

import ipaddress
import socket
import struct
import time


INTERFACE = "eth0"
SUBNET = "172.30.10.0/24"
LOCAL_IP = "172.30.10.20"
ETHERTYPE_ARP = 0x0806


def format_mac(mac_address: bytes) -> str:
    """Converte bytes de um endereço MAC para texto."""
    return ":".join(f"{byte:02x}" for byte in mac_address)


def get_local_mac() -> bytes:
    """Obtém o MAC da interface de rede do interceptador."""
    with open(f"/sys/class/net/{INTERFACE}/address") as file:
        mac_address = file.read().strip()

    return bytes.fromhex(mac_address.replace(":", ""))


def build_arp_request(source_mac: bytes, target_ip: str) -> bytes:
    """Constrói um quadro Ethernet com uma requisição ARP."""

    # Cabeçalho Ethernet: MAC destino, MAC origem e EtherType.
    ethernet_header = struct.pack(
        "!6s6sH",
        b"\xff" * 6,
        source_mac,
        ETHERTYPE_ARP,
    )

    # Mensagem ARP: Ethernet, IPv4, tamanhos e operação REQUEST.
    arp_message = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        1,
        source_mac,
        socket.inet_aton(LOCAL_IP),
        b"\x00" * 6,
        socket.inet_aton(target_ip),
    )

    return ethernet_header + arp_message


def scan_network() -> dict[str, str]:
    """Envia ARP Requests e coleta as respostas dos dispositivos."""

    discovered = {}
    source_mac = get_local_mac()
    network = ipaddress.ip_network(SUBNET)

    with socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(ETHERTYPE_ARP),
    ) as sock:
        sock.bind((INTERFACE, 0))

        # Consulta os endereços utilizáveis da sub-rede.
        for ip_address in network.hosts():
            if str(ip_address) == LOCAL_IP:
                continue

            request = build_arp_request(source_mac, str(ip_address))
            sock.send(request)

        # Aguarda respostas por até três segundos.
        deadline = time.monotonic() + 3

        while time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))

            try:
                frame, _ = sock.recvfrom(65535)
            except socket.timeout:
                break

            if len(frame) < 42 or frame[12:14] != b"\x08\x06":
                continue

            (
                hardware_type,
                protocol_type,
                hardware_size,
                protocol_size,
                operation,
                sender_mac,
                sender_ip,
                target_mac,
                target_ip,
            ) = struct.unpack("!HHBBH6s4s6s4s", frame[14:42])

            # Aceita somente ARP Replies Ethernet/IPv4 para nós.
            if (
                hardware_type != 1
                or protocol_type != 0x0800
                or hardware_size != 6
                or protocol_size != 4
                or operation != 2
                or socket.inet_ntoa(target_ip) != LOCAL_IP
            ):
                continue

            ip = socket.inet_ntoa(sender_ip)
            discovered[ip] = format_mac(sender_mac)

    return discovered


def main() -> None:
    print(f"Scanning network {SUBNET}...")

    devices = scan_network()

    print("\nDiscovered devices:")

    for ip, mac in devices.items():
        print(f"IP: {ip} | MAC: {mac}")

    if len(devices) < 2:
        print("Not enough devices found.")
        return

    # Permite selecionar os papéis do laboratório.
    victim_ip = input("\nVictim IP: ").strip()
    gateway_ip = input("Gateway IP: ").strip()

    if (
        victim_ip not in devices
        or gateway_ip not in devices
        or victim_ip == gateway_ip
    ):
        print("Invalid device selection.")
        return

    print(f"\nSelected victim: {victim_ip}")
    print(f"Selected gateway: {gateway_ip}")


if __name__ == "__main__":
    main()
