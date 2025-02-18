from core.logger import get_logger
from scapy.all import *
import binascii

class Extractor(object):
    def __init__(self, obj):
        self.obj = obj
        self.input = self.obj.seed
        self.layer = "TCP"
        self.field = "load"
        self.PORT = 502
        self.verbosity = self.r0obj.log_level

        self.logger = get_logger("New Extractor", self.verbosity)

    def extract_modbus(self, extracted_packets):
        pass

    def generate_new_modbus(self):
        try:
            packets = rdpcap(self.input)
        except Exception as e:
            self.logger.error(e)
            self.logger.warning("[X] Unable to read file")
            return False
        
        self.
        
