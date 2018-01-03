This program is made to detect the denial of service or disconnection or de-authentication requests that are sent to a wifi interface for hacking and capturing its packets.
Scapy module used in python is required for successful implementation of this program.

Class De-authentication detector is used as a placeholder for sniffing start function, extract packet function and print value function.

The 'main' function in the same class is used as an initializer which initializes the class and instantiates the objects accordingly.

The main control loop trigger is "if __name__=='__main__'"

extract_packets_funct is a function specifically designed to detect the packets that are sent for DOS attacks (Deaunthetication packets in case of Wifi attacks).

sniff_funct is a function that is used to create the Scapy.sniff function for sniffing the extracted packets.

value_print_funct is used to print the values or results of the sniffing and extraction of de-authentication packets.

Future Developments:

Future developments will be added later on, after they are planned.


Testing Underway.
Repository to be made public on: January 14, 2018


This repository will be private until then.
