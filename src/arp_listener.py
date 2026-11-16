
"""Etapa 2: captura e decodifica mensagens ARP no laboratório Docker.

Executar dentro do contêiner Linux "interceptor" (requer NET_RAW).
"""

import socket
import struct


ETH_P_ALL = 0x0003
ETHERTYPE_ARP = 0x0806


def format_mac(mac_address: bytes) -> str:
    """Converte seis bytes de um endereço MAC para hexadecimal."""
    return ":".join(f"{byte:02x}" for byte in mac_address)


def format_ip(ip_address: bytes) -> str:
    """Converte quatro bytes IPv4 para a representação decimal."""
    return ".".join(str(byte) for byte in ip_address)


def main() -> None:
    # Cria um raw socket para receber quadros Ethernet no Linux.
    with socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(ETH_P_ALL),
    ) as sniffer:
        sniffer.bind(("eth0", 0))

        print("Listening for ARP frames on eth0. Press Ctrl+C to stop.", flush=True)

        try:
            while True:
                # Recebe um quadro da interface de rede.
                frame, _ = sniffer.recvfrom(65535)

                # Verifica se existe um cabeçalho Ethernet completo.
                if len(frame) < 14:
                    continue

                # Interpreta os 14 bytes do cabeçalho Ethernet.
                destination_mac, source_mac, ether_type = struct.unpack(
                    "!6s6sH", frame[:14]
                )

                # Ignora quadros que não transportam ARP.
                if ether_type != ETHERTYPE_ARP:
                    continue

                # Verifica se existem 28 bytes de ARP após o Ethernet.
                if len(frame) < 42:
                    continue

                # Seleciona apenas os bytes da mensagem ARP.
                arp_data = frame[14:42]

                # Interpreta os nove campos da mensagem ARP.
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
                ) = struct.unpack("!HHBBH6s4s6s4s", arp_data)

                # Aceita somente mensagens ARP para Ethernet e IPv4.
                if (hardware_type, protocol_type, hardware_size, protocol_size) != (
                    1, 0x0800, 6, 4
                ):
                    continue

                # Identifica se é uma requisição ou resposta.
                operation_name = {
                    1: "REQUEST",
                    2: "REPLY",
                }.get(operation, "UNKNOWN")

                # Exibe os dados encontrados na mensagem ARP.
                print(
                    f"ARP {operation_name} | "
                    f"sender_ip={format_ip(sender_ip)} | "
                    f"sender_mac={format_mac(sender_mac)} | "
                    f"target_ip={format_ip(target_ip)} | "
                    f"target_mac={format_mac(target_mac)}",
                    flush=True,
                )

        except KeyboardInterrupt:
            print("\nCapture stopped. No ARP settings were changed.")


if __name__ == "__main__":
    main()
