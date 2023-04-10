from scapy.all import *
from datetime import datetime

from scapy.layers.inet import TCP, IP

# List of ports to listen on
PORTS = [22, 80, 443]


# Logging function to log received data
def log_data(port, data):
    print(f"Data received on port {port}: {data.decode()}")
    with open(f"honeypot_{port}_log.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] Data received on port {port}: {data.decode()}\n")


# Intrusion detection function
def intrusion_detection(pack):
    # Customize intrusion detection rules as needed
    if pack[TCP].flags == 'S' and pack[TCP].dport in PORTS:
        print(f"Intrusion detected! SYN scan on port {pack[TCP].dport} from {pack[IP].src}")
        with open("intrusion_alerts.txt", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Intrusion detected! SYN scan on port {pack[TCP].dport} from {pack[IP].src}\n")


# Honeypot class
class Honeypot:
    def __init__(self, host='0.0.0.0', max_connections=5):
        self.host = host
        self.max_connections = max_connections

    def start(self):
        for port in PORTS:
            # Create a new thread for each port
            t = threading.Thread(target=self.listen, args=(port,))
            t.start()

        # Start packet capture
        sniff(filter=f"tcp and (dst port {' or '.join(map(str, PORTS))})", prn=intrusion_detection)

    def listen(self, port):
        # Create a socket and bind it to the specified port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, port))
        s.listen(self.max_connections)
        print(f"Listening on port {port}...")

        while True:
            try:
                # Accept incoming connection
                conn, addr = s.accept()
                print(f"Incoming connection from {addr[0]}:{addr[1]} on port {port}")

                # Receive data from the connection
                data = conn.recv(1024)
                if data:
                    # Log received data
                    log_data(port, data)

                # Close the connection
                conn.close()

            except KeyboardInterrupt:
                print("Exiting...")
                s.close()
                return


if __name__ == '__main__':
    honeypot = Honeypot()
    honeypot.start()
