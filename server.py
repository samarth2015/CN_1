import socket
from scapy.all import *



HOST = "127.0.0.1" 
PORT = 9998

class CustomDNSHeader(Packet):
    name = "CustomDNSHeader"
    fields_desc = [
        StrFixedLenField("timestamp_id", "", 8)
    ]

IP_Pool = [
"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while(True):
        print(f"Server listening on {HOST}:{PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(4096) 

            if data:
                
                received_packet = CustomDNSHeader(data) 
                
                print("\n--- Received Packet at Server ---")
                received_packet.show()


                header_value = received_packet[CustomDNSHeader].timestamp_id.decode()
                print(f"Extracted Header Value: {header_value}")


                hours = int(header_value[:2])
                id = int(header_value[-2:])

                if(4<=hours<=11):
                    new_pool = IP_Pool[0:5]
                    resolved_ip = new_pool[id % len(new_pool)]
                elif(12<=hours<=19):
                    new_pool = IP_Pool[5:10]
                    resolved_ip = new_pool[id % len(new_pool)]
                else:
                    new_pool = IP_Pool[10:15]
                    resolved_ip = new_pool[id % len(new_pool)]

                conn.sendall(resolved_ip.encode())