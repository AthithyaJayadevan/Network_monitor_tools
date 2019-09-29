import socket
import sys

#creating a socket instance
try:
   s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

except socket.error, msg:
    print('Socket could not be created !!')
    sys.exit()

while True:
    packet=s.recvfrom(65565)

    packet=packet[0]
    
    #packet header info
    ip_header = packet[0:20]

    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    ihl = version_ihl &amp
    
    ttl=iph[5]
    protocol=iph[6]

    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    print(a_addr)
    print(d_addr)

    tcp_header = packet[]



