from scapy.all import Ether, IP, TCP, Raw, wrpcap, rdpcap
import random
import os
import logging
from collections import defaultdict
import numpy as np
from sklearn.cluster import KMeans  

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class MLFuzzer:
    def __init__(self):
        self.patterns = defaultdict(list) 
        self.model = None

    def train(self, pcap_dir):
        """Learn patterns from .pcap files."""
        logging.info("[+] Learning patterns from .pcap files...")
        
        if not os.path.isdir(pcap_dir):
            logging.error(f"[-] Directory not found: {pcap_dir}")
            return
        
        try:
            features = []
            for root, _, files in os.walk(pcap_dir):
                for file in files:
                    if file.endswith(".pcap"):
                        pcap_file = os.path.join(root, file)
                        logging.info(f"[+] Processing {pcap_file}")
                        features.extend(self.extract_features(pcap_file))
            
            self.train_model(features)
            logging.info("[+] Patterns learned and model trained successfully.")
        except Exception as e:
            logging.error(f"[-] Error during training: {e}")

    def extract_features(self, pcap_file):
        """Extract features from a single .pcap file."""
        features = []
        valid_function_codes = [1, 2, 3, 4, 5, 6, 15, 16]  
        
        try:
            packets = rdpcap(pcap_file)
            logging.info(f"[+] Processing {pcap_file} with {len(packets)} packets")
            for packet in packets:
                if TCP in packet and Raw in packet:
                    payload = packet[Raw].load
                    if packet[TCP].dport == 502: 
                        if len(payload) >= 8:  
                            func_code = payload[7] 
                            if func_code in valid_function_codes:
                                features.append([func_code])
        except Exception as e:
            logging.error(f"[-] Error processing {pcap_file}: {e}")
        return features

    def train_model(self, features):
        """Train a machine learning model on the extracted features."""
        if not features:
            logging.error("[-] No features extracted for training.")
            return
        
        self.model = KMeans(n_clusters=3)
        self.model.fit(np.array(features))
        logging.info("[+] Model trained successfully.")

    def generate_modbus_packet(self):
        """Generate a Modbus packet based on learned patterns."""
        valid_function_codes = [1, 2, 3, 4, 5, 6, 15, 16, 23]

        if self.model:
            func_code = int(self.model.cluster_centers_[random.randint(0, len(self.model.cluster_centers_) - 1)][0])
            if func_code not in valid_function_codes:
                func_code = random.choice(valid_function_codes)
        else:
            func_code = random.choice(valid_function_codes)

        if func_code in [1, 2, 3, 4]: 
            start_addr = random.randint(0, 65535)
            quantity = random.randint(1, 200) 
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                start_addr.to_bytes(2, byteorder="big") +
                quantity.to_bytes(2, byteorder="big")
            )
        elif func_code in [5, 6]: 
            addr = random.randint(0, 65535)
            value = random.randint(0, 65535)
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                addr.to_bytes(2, byteorder="big") +
                value.to_bytes(2, byteorder="big")
            )
        elif func_code in [15, 16]: 
            start_addr = random.randint(0, 65535)
            quantity = random.randint(1, 100)  
            byte_count = (quantity + 7) // 8 if func_code == 15 else quantity * 2
            values = bytes([random.randint(0, 255) for _ in range(byte_count)])
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                start_addr.to_bytes(2, byteorder="big") +
                quantity.to_bytes(2, byteorder="big") +
                byte_count.to_bytes(1, byteorder="big") +
                values
            )
        elif func_code == 23:  
            read_start_addr = random.randint(0, 65535)
            read_quantity = random.randint(1, 125)  
            write_start_addr = random.randint(0, 65535)
            write_quantity = random.randint(1, 100) 
            write_byte_count = write_quantity * 2
            write_values = bytes([random.randint(0, 255) for _ in range(write_byte_count)])

            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                read_start_addr.to_bytes(2, byteorder="big") +
                read_quantity.to_bytes(2, byteorder="big") +
                write_start_addr.to_bytes(2, byteorder="big") +
                write_quantity.to_bytes(2, byteorder="big") +
                write_byte_count.to_bytes(1, byteorder="big") +
                write_values
            )
        else:
            raise ValueError(f"Unsupported function code: {func_code}")

        trans_id = random.randint(0, 65535)  
        proto_id = 0x0000  
        length = len(pdu) + 1  
        unit_id = 0x01 

        mbap_header = (
            trans_id.to_bytes(2, byteorder="big") +
            proto_id.to_bytes(2, byteorder="big") +
            length.to_bytes(2, byteorder="big") + 
            unit_id.to_bytes(1, byteorder="big")
        )

        print(f"MBAP Header Length: {len(mbap_header)}")

        modbus_packet = mbap_header + pdu

        return Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=502, sport=random.randint(1024, 65535), flags="PA") / Raw(load=modbus_packet)
    def generate_corpus(self, num_samples=20, output_file="new_packets.pcap", protocol="modbus"):
        """Generate a corpus of synthetic packets."""
        synthetic_packets = []
        for _ in range(num_samples):
            if protocol == "modbus":
                packet = self.generate_modbus_packet()
            else:
                raise ValueError(f"Unsupported protocol: {protocol}")
            synthetic_packets.append(packet)
        wrpcap(output_file, synthetic_packets)
        logging.info(f"[+] Generated {num_samples} {protocol} packets and saved to {output_file}")


