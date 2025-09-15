import socket
from scapy.all import *

host="127.0.0.1"
port=9999

class DNSHeader(Packet): #custom DNS header with fixed 8-byte fielf for timestamp + id
    name="DNSHeader"
    fields_desc=[StrFixedLenField("timestamp_id", "", 8)]

# IP addresses to return as response
IPs=[
"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

#create a TCP socket server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host,port)) #bind to host and port
    s.listen() #start listening for connections

    while(True):
        print(f"Server is listening on host {host} at port {port}...")
        print()

        c, addr=s.accept()

        with c:
            print(f"connected with {addr}")
            data=c.recv(4096)
            if data:
                p=DNSHeader(data) #parse received packet as DNS Header
                header=p[DNSHeader].timestamp_id.decode()

                #extract hours(first 2 chars) and ID(last 2 chars)
                hours=int(header[:2]) 
                id=int(header[-2:])

                #select IP pool based on time of the day
                if(4<=hours<=11):
                    new_IPs=IPs[0:5]
                    answer_IP=new_IPs[id%len(new_IPs)]
                elif(12<=hours<=19):
                    new_IPs=IPs[5:10]
                    answer_IP=new_IPs[id%len(new_IPs)]
                else:
                    new_IPs=IPs[10:15]
                    answer_IP=new_IPs[id%len(new_IPs)]
                
                c.sendall(answer_IP.encode()) #send chosen IP back to client

