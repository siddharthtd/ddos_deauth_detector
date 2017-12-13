Field = {'count': (5, False), 'iface': (None, True), 'timeout': (None, False)}

import sys
import scapy.all as scapy


class Deauth_detect_class:

    def __init__(self, *arguments, **keywords):

        self.arguments = arguments
        self.keywords = keywords
        self.data = {}
        self.sniff_funct()

    def extract_packets_funct(self, pkt):

        if pkt.haslayer(scapy.Dot11Deauth):
            vic1 = pkt.addr1
            vic2 = pkt.addr2
            if str([vic1, vic2]) in self.data.keys():
                self.data[str([vic1, vic2])] = self.data[str([vic1, vic2])] + 1
            else:
                self.data[str([vic1, vic2])] = 1
        self.value_print_funct()
        return

    def value_print_funct(self):
        count = 0
        for a, b in self.data.iteritems():
            vic1, vic2 = eval(a)
            print("\nDe-authentication Packet:{}<--->{}\nPackets:{}".format(vic1, vic2, b))
            count += 1

        sys.stdout.write("\033[{}A".format(line))
        return

    def sniff_funct(self):
        scapy.sniff(prn=self.extract_packets_funct, *self.arguments, **self.keywords)
        return


def main(*arguments, **keywords):
    Deauth_detect_class(*arguments, **keywords)
    return


if __name__ == '__main__':
    if len(sys.argv) == 2:
        main(iface=sys.argv[1])
    else:
        print("[Error]Please Provide Monitor Mode Interface Name ALso \n\n\t:~# sudo {} mon0".format(sys.argv[0]))
