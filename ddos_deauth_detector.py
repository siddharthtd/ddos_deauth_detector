Field={'count': (5,False), 'iface': (None, True), 'timeout': (None, False)}

import sys
import scapy


class DeauthenticationDetector:

    def __init__(self, *args, **kwargs):

        self.args = args
        self.kwargs = kwargs
        self.data={}
        self.Sniffing_Start()


    def extract_packets(self, pkt):

        if pkt.haslayer(scapy.Dot11Deauth):
            victim1 = pkt.addr2
            victim2 = pkt.addr1
            if str([victim1, victim2]) in self.data.keys():
                self.data[str([victim1, victim2])] = self.data[str([victim1, victim2])] + 1
            else:
                self.data[str([victim1, victim2])] = 1
            self.print_values()
    return

    