import socket
import struct
import textwrap

def main():
    # Get the raw socket data and format with nhtohs
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Listen for data moving across the network. 65536 is the max buffer size.
    while True:
        raw_data, address = connection.recvfrom(65536)
        # Store the raw data 
        dest_mac, src_mac, eth_protocol, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol:{}'.format(dest_mac, src_mac, eth_proto)) 


# Unpack an ethernet frame
def ethernet_frame(data):
    """Take an ethernet frame, unpack it and return the results in readable form."""
    # '!' means we're treating it as network data. 6s means 6 bytes, the length of the MAC. H is an integer, and the data is collecting the first 14 bytes
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
def IPv4_packet():
    # extract the version and the header length
    version_header_length = data[0]
    # bitshift the version by 4
    version = version_header_length >> 4
    # Find the header length, because the data comes directly after the header
    header_length = (version_header_length & 15) * 4
    # Disect the packet into variables, the data is in protocol
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target)

# Returns formatted IPv4 address
def ipv4_format(address):
    return '.'.join(map(str, address))

# Unpack the ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack the TCP segment.
def tcp_seg(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved) = struct.unpack('! H H L L H', data[:14])
    # We have to unpack the offset and reserve in a weird way because they are part of the same segment
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:] 