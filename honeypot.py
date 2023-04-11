import tkinter
from tkinter import ttk
from scapy.all import *
from datetime import datetime

from scapy.layers.inet import TCP, IP

# List of ports to listen on
PORTS = [22, 80, 443]


class PortListener:
    # Logging function to log received data
    @staticmethod
    def log_data(host, addr, port, data, tree):
        print(f"Data received on port {port}: {data.decode()}")
        with open(f"honeypot_{port}_log.txt", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Data received on port {port}: {data.decode()}\n")
            tree.insert("", "end", values=[timestamp, port, addr, host, data.decode()])

    # Intrusion detection function
    @staticmethod
    def intrusion_detection(pack, tree):
        # Customize intrusion detection rules as needed
        if pack[TCP].flags == 'S' and pack[TCP].dport in PORTS:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] Intrusion detected! SYN scan. details: {{port={pack[TCP].dport}, srcIP={pack[IP].src}, dstIP={pack[IP].dst}}}")
            with open("intrusion_alerts.txt", "a") as f:
                f.write(f"[{timestamp}] Intrusion detected! SYN scan. details: {{port={pack[TCP].dport}, srcIP={pack[IP].src}, dstIP={pack[IP].dst}}}\n")
                tree.insert("", "end", values=[timestamp, pack[TCP].dport, pack[IP].src, pack[IP].dst, "SYN scan"])

        if pack.haslayer(Raw):
            payload = pack[Raw].load.decode(errors='ignore')
            if 'cmd.exe' in payload or 'root' in payload or 'sh' in payload:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] Intrusion detected! Suspicious payload. details: {{port={pack[TCP].dport}, srcIP={pack[IP].src}, dstIP={pack[IP].dst}}}")
                with open("intrusion_alerts.txt", "a") as f:
                    f.write(f"[{timestamp}] Intrusion detected! Suspicious payload. details: {{port={pack[TCP].dport}, srcIP={pack[IP].src}, dstIP={pack[IP].dst}}}\n")
                    tree.insert("", "end", values=[timestamp, pack[TCP].dport, pack[IP].src, pack[IP].dst + "", "Suspicious payload"])


class SniffThread(Thread):
    def __init__(self, tree):
        super().__init__()
        self.tree = tree

    def run(self) -> None:
        try:
            # Start packet capture
            sniff(filter=f"tcp and (dst port {' or '.join(map(str, PORTS))})",
                  prn=lambda pack: PortListener.intrusion_detection(pack, self.tree))

        except KeyboardInterrupt:
            print("Closing Sniff...")
            return


# Honeypot class
class Honeypot:
    def __init__(self, host='0.0.0.0', max_connections=5):
        self.host = host
        self.max_connections = max_connections

    def start(self):
        try:
            root = tkinter.Tk()
            root.title("Honeypot")
            root.geometry("1000x400")

            # Create trace table
            tree = ttk.Treeview(root, columns=("Timestamp", "Port", "Source IP", "Destination Port", "Result"), show="headings")
            tree.heading("Timestamp", text="Timestamp")
            tree.heading("Port", text="Port")
            tree.heading("Source IP", text="Source IP")
            tree.heading("Destination Port", text="Destination IP")
            tree.heading("Result", text="Result")
            tree.pack(expand=True, fill="both")

            for port in PORTS:
                # Create a new thread for each port
                t = threading.Thread(target=self.listen, args=(port, tree))
                t.start()
                time.sleep(0.1)

            SniffThread(tree).start()

            root.mainloop()

        except KeyboardInterrupt:
            print("Closing main app...")
            return

    def listen(self, port, tree):
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
                    PortListener.log_data(conn.getsockname(), addr[0], port, data, tree)

                    # Send a response to the client
                    response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Welcome Hacker!</h1></body></html>".encode()
                    conn.sendall(response)

                # Close the connection
                conn.close()

            except KeyboardInterrupt:
                print("Exiting...")
                s.close()
                return


if __name__ == '__main__':
    Honeypot().start()
