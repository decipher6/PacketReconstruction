from scapy.all import rdpcap, IP, TCP
import binascii


def extract_http_data(packet):
   """Extracts HTTP data from a TCP packet."""
   # Check if the packet has TCP and IP layers
   if packet.haslayer(IP) and packet.haslayer(TCP):
       ip_src = packet[IP].src
       ip_dst = packet[IP].dst
       tcp_sport = packet[TCP].sport
       tcp_dport = packet[TCP].dport
      
       # Check for HTTP payload (usually starts with 'HTTP/1.1' or 'GET' or 'POST')
       if packet.haslayer('Raw'):
           payload = packet['Raw'].load.decode(errors='ignore')
           if "HTTP" in payload or "GET" in payload or "POST" in payload:
               return {
                   "src_ip": ip_src,
                   "dst_ip": ip_dst,
                   "src_port": tcp_sport,
                   "dst_port": tcp_dport,
                   "http_payload": payload
               }
   return None


def reconstruct_packet(packet_data):
   """Reconstructs and prints out an HTTP request from extracted data."""
   if packet_data:
       print(f"Reconstructed HTTP Packet:")
       print(f"Source IP: {packet_data['src_ip']}")
       print(f"Destination IP: {packet_data['dst_ip']}")
       print(f"Source Port: {packet_data['src_port']}")
       print(f"Destination Port: {packet_data['dst_port']}")
       print(f"HTTP Data:\n{packet_data['http_payload']}")
   else:
       print("No HTTP data found.")


def main(pcap_file):
   """Main function to read and process packets."""
   packets = rdpcap(pcap_file)  # Read pcap file
  
   for packet in packets:
       # Try extracting HTTP data from each packet
       packet_data = extract_http_data(packet)
      
       # If HTTP data is found, reconstruct and print it
       if packet_data:
           reconstruct_packet(packet_data)
           break  # We only reconstruct one packet for now


if __name__ == "__main__":
   # Provide the path to the pcap file with captured traffic
   pcap_file = 'captured_traffic.pcap'
   main(pcap_file)
