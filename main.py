import scapy.all as scapy  # pip install scapy
import argparse

# Função para imprimir os resultados
def print_result(results_list):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

# Função para obter os argumentos
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify target IP address or range")
    options = parser.parse_args()
    return options


# Função para escanear a rede
def scan(ip):
    # Cria um pacote ARP
    arp_request = scapy.ARP(pdst=ip)

    # Cria um quadro Ethernet para o pacote ARP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combina o quadro Ethernet e o pacote ARP
    arp_request_broadcast = broadcast/arp_request

    # Envia o pacote e recebe a resposta
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Lista para armazenar os resultados
    clients_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


options = get_arguments()  # Obtém os argumentos
target_ip = options.target  # Obtém o alvo

if not target_ip:  # Se não houver alvo
    print("[-] Por favor, especifique o alvo. Use --help para mais informações.")
    exit()

scan_result = scan(target_ip)
print_result(scan_result)
