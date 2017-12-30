Field={'count': (5,False), 'iface': (None, True), 'timeout': (None, False)}

import sys
import scapy


class DeauthenticationDetector:

    def __init__(self, *args, **kwargs):
        
        self.args = args
        self.kwargs = kwargs
        self.data={}
        self.Sniffing_Start()
