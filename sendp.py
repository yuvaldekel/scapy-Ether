from scapy.all import Ether, IP, ICMP, ARP, Raw, sendp, srp1

MY_MAC = '00:28:f8:6b:ea:cc'
MY_IP = '10.20.50.101'
ROUTER_IP = '10.20.254.253'
ROUTER_MAC = 'e0:db:55:13:94:cc'
BROADCAST ='ff:ff:ff:ff:ff:ff'

def alphabet_list(start = "A", end = 'z'):
    alphabet = []
    A_ascii = ord(start)
    Z_ascii = ord(end)

    for ascii_rep in range(A_ascii, Z_ascii + 1):
        letter = ascii_rep.to_bytes().decode('ascii')
        if letter.isalpha():
            alphabet.append(letter)
    
    return ''.join(alphabet)       

def main():
    alphabet = alphabet_list()

    request_arp = Ether(dst = BROADCAST, type = 2054)/ARP(hwlen=6, plen=4, hwsrc=MY_MAC, psrc=MY_IP, pdst=ROUTER_IP)
    reply_arp = srp1(request_arp)
    
    router_mac = reply_arp[ARP].hwsrc

    ping_request_frame = Ether(dst = router_mac, type = 2048)/IP(dst = "www.google.com")/ICMP(type = 8, code = 0, id = 1, seq = 1)/Raw(alphabet)
    
    ping_reply_frame = srp1(ping_request_frame, timeout = 5)
    ping_reply_frame.show()

if __name__ == "__main__":
    main()