Field = {'count': (5, False), 'iface': (None, True), 'timeout': (None, False)}

import sys
import scapy.all as scapy


class Deauth_det:

    def __init__(self, *args, **kwargs):

        self.args = args
        self.kwargs = kwargs
        self.data = {}
        self.Sniffing_Start()

    def extract_packets(self, pkt):

        if pkt.haslayer(scapy.Dot11Deauth):
            victim1 = pkt.addr1
            victim2 = pkt.addr2
            if str([victim1, victim2]) in self.data.keys():
                self.data[str([victim1, victim2])] = self.data[str([victim1, victim2])] + 1
            else:
                self.data[str([victim1, victim2])] = 1
        self.print_values()
        return

    def print_values(self):
        count = 0
        for a,b in self.data.iteritems():
            v1, v2 = eval(a)
            print("\nDe-authentication Packet:{}<--->{}\nPackets:{}".format(v1, v2, b))
            count += 1

        # Backspace Trick
        sys.stdout.write("\033[{}A".format(line))
        return

    def Sniffing_Start(self):
        scapy.sniff(prn=self.extract_packets, *self.args, **self.kwargs)
        return


def main(*args, **kwargs):
    Deauth_det(*args, **kwargs)
    return


if __name__ == '__main__':
    if len(sys.argv) == 2:
        main(iface=sys.argv[1])
    else:
        print("[Error]Please Provide Monitor Mode Interface Name ALso \n\n\t:~# sudo {} mon0".format(sys.argv[0]))
