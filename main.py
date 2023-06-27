import scapy.all as sc


def scann_ip(ip):
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    affirm_recs, = sc.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    print("IP\t\t\tMAC ADDRESS")
    for element in affirm_recs:
        print(element[1].psrc)
        print(element[1].hwsrc)
    print("<---------------------------------------------->")


scann_ip("192.168.1.11/24")
