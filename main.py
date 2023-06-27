import scapy.all as sc


def scann_ip(ip):
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    affirm_recs, = sc.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

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


scan_result = scann_ip("192.168.1.11/24")
print_result(scan_result)
