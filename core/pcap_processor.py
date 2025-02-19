from scapy.all import rdpcap, TCP, Raw
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class PCAPProcessor:
    def __init__(self):
        self.patterns = defaultdict(list)  

    def extract_features(self, pcap_file):
        """Extract patterns from a single .pcap file."""
        try:
            packets = rdpcap(pcap_file)
            logging.info(f"[+] Processing {pcap_file} with {len(packets)} packets")
            for packet in packets:
                if TCP in packet and Raw in packet:
                    payload = packet[Raw].load
                    if packet[TCP].dport == 502:  
                        if len(payload) >= 8:  
                            func_code = payload[7]  
                            self.patterns["modbus_func_codes"].append(func_code)
                            logging.debug(f"[+] Modbus Function Code: {func_code}")
                    elif packet[TCP].dport == 20000:  
                        if len(payload) >= 10: 
                            ctrl = payload[2] 
                            self.patterns["dnp3_ctrl_codes"].append(ctrl)
                            logging.debug(f"[+] DNP3 Control Code: {ctrl}")
        except Exception as e:
            logging.error(f"[-] Error processing {pcap_file}: {e}")

    def get_patterns(self):
        """Return the analyzed patterns."""
        return self.patterns