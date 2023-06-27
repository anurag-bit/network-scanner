import scapy.all as sc


def scann_ip(ip):
    sc.arping(ip)


scann_ip("192.168.1.11")
