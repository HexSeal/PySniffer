import socket
import struct
import textwrap

# Tabs for visual hierarchy when processing network data
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    # Get the raw socket data and format with ntohs
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Listen for data moving across the network. 65536 is the max buffer size.
    while True:
        raw_data, address = connection.recvfrom(65536)
        # Store the raw data 
        dest_mac, src_mac, eth_protocol, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol:{}'.format(dest_mac, src_mac, eth_protocol)) 
        
        # 8 for IPv4
        if eth_protocol == 8:
            (version, header_length, ttl, proto, src, target, data) = IPv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            
            # 1 = ICMP packet
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))
            
            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24])
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))

                if len(data) > 0:
                    # HTTP
                    if src_port == 80 or dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, data))
            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, data))


# Unpack an ethernet frame
def ethernet_frame(data):
    """Take an ethernet frame, unpack it and return the results in readable form."""
    # '!' means we're treating it as network data. 6s means 6 bytes, the length of the src and dest MAC. H is the type(2 bytes), for a total of the first 14 bytes
    dest_mac, src_mac, pack_type = struct.unpack('! 6s 6s H', data[:14])
    # htons converts the bytes based on compatible endianness
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(pack_type), data[14:]

# Return a properly formatted MAC address(AA:BB:CC:DD:EE:FF)
def format_mac(byte_address):
    # Get the groups of bytes in the address, 2 each seperated by decimals. 
    bytes_str = map('{:02x}'.format, byte_address)
    # Join the byte strings with a colon
    return ':'.join(bytes_str).upper()

# Get the individual packet data
def IPv4_packet(data):
    # extract the version and the header length
    version_header_length = data[0]
    # bitshift the version by 4
    version = version_header_length >> 4
    # Find the header length, because the data comes directly after the header
    header_length = (version_header_length & 15) * 4
    # Dissect the packet into variables, the data is in protocol
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4_format(src), ipv4_format(target), data[header_length:]

# Returns formatted IPv4 address
def ipv4_format(address):
    return '.'.join(map(str, address))

# Unpack the ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack the TCP segment.
def tcp_seg(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    # We have to unpack the offset and reserve in a weird way because they are part of the same segment
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Formats multi-line data to make it more readable
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()