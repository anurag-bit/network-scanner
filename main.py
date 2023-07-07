import scapy.all as sc
import argparse as option


def get_arguments():
    # Define Variable consistency throughout scope!
    global IP
    # Object Parser instance for Parsing arguments
    parser = option.ArgumentParser()
    # parser argument
    parser.add_argument("-t", "--target", dest="ip")
    (IP) = parser.parse_args()
    return IP


def scann_ip(ip):
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    affirm_recs = sc.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_rec = []
    for element in affirm_recs:
        client_dict = {"IP": element[1].psrc, "mac": element[1].hwsrc}
        clients_rec.append(client_dict)
        return clients_rec


def print_result(result_list):
    print("IP\t\t\tMAC ADDRESS\n<---------------------------------------------->")
    for client in result_list:
        print(client["IP"] + "\t\t" + client["mac"])

    return



target_ip = get_arguments()
scan_result = scann_ip(target_ip.IP)
print_result(scan_result)
