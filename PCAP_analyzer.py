import struct
import socket

def parse_pcap(file):
    connections = {}

    with open(file, 'rb') as f:
        # Skip the global header (24 bytes for standard pcap)
        f.read(24)

        while True:
            # Read the packet header (16 bytes)
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break  # End of file reached

            # Parse the packet header for timestamp and length
            timestamp_sec, timestamp_usec, incl_len, orig_len = struct.unpack('=IIII', packet_header)
            timestamp = timestamp_sec + timestamp_usec / 1e6  # Convert to float seconds

            # Read packet data based on incl_len
            buf = f.read(incl_len)
            if len(buf) < incl_len:
                break

            # Parse Ethernet header (first 14 bytes)
            eth_header = buf[:14]
            eth_type = struct.unpack('!H', eth_header[12:14])[0]

            if eth_type == 0x0800:  # IPv4
                # Parse IP header
                ip_header = buf[14:34]
                version_ihl, tos, total_len, identification, flags_offset, ttl, proto, checksum, src_ip, dst_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)
                src_ip = socket.inet_ntoa(src_ip)
                dst_ip = socket.inet_ntoa(dst_ip)

                if proto == 6:  # TCP
                    # Parse TCP header
                    tcp_header = buf[34:54]
                    src_port, dst_port, seq, ack, offset_res_flags, win, checksum, urg_ptr = struct.unpack('!HHLLHHHH', tcp_header)
                    offset = (offset_res_flags >> 12) * 4
                    flags = offset_res_flags & 0x01FF

                    # Create connection key
                    src = (src_ip, src_port)
                    dst = (dst_ip, dst_port)
                    connection_key = tuple(sorted([src, dst]))

                    if connection_key not in connections:
                        connections[connection_key] = {
                            'start_time': None,
                            'end_time': None,
                            'packets_src_to_dst': 0,
                            'packets_dst_to_src': 0,
                            'bytes_src_to_dst': 0,
                            'bytes_dst_to_src': 0,
                            'window_sizes': [],
                            'rtt_times': [],
                            'syn_count': 0,
                            'fin_count': 0,
                            'reset': False,
                            'established_before_capture': False
                        }

                    conn = connections[connection_key]

                    # Check flags
                    if flags & 0x02:  # SYN flag
                        conn['syn_count'] += 1
                        if not conn['start_time']:
                            conn['start_time'] = timestamp
                    if flags & 0x01:  # FIN flag
                        conn['fin_count'] += 1
                        conn['end_time'] = timestamp
                    if flags & 0x04:  # RST flag
                        conn['reset'] = True
                    if flags & 0x10 and not (flags & 0x02):  # ACK flag, but not SYN-ACK
                        if conn['start_time']:
                            rtt = timestamp - conn['start_time']
                            conn['rtt_times'].append(rtt)

                    if conn['syn_count'] == 0 and conn['start_time'] is None:
                        conn['established_before_capture'] = True

                    # Count packets and bytes
                    if src == (src_ip, src_port):
                        conn['packets_src_to_dst'] += 1
                        conn['bytes_src_to_dst'] += len(buf) - (14 + offset)
                    else:
                        conn['packets_dst_to_src'] += 1
                        conn['bytes_dst_to_src'] += len(buf) - (14 + offset)

                    conn['window_sizes'].append(win)

    return connections

def determine_state(conn):
    syn = conn['syn_count']
    fin = conn['fin_count']
    return f"S{syn}F{fin}" if not conn['reset'] else 'R'

def calculate_statistics(connections):
    total_duration = 0
    complete_connections = 0
    reset_connections = 0
    open_connections = 0
    before_capture_connections = 0

    durations = []
    packet_counts = []
    window_sizes = []
    rtt_times = []

    for conn_key, conn in connections.items():
        if conn['reset']:
            reset_connections += 1
        elif conn['established_before_capture']:
            before_capture_connections += 1
        elif conn['syn_count'] >= 1 and conn['fin_count'] >= 1:
            complete_connections += 1
            if conn['start_time'] and conn['end_time']:
                duration = conn['end_time'] - conn['start_time']
                durations.append(duration)
                total_duration += duration
        elif conn['syn_count'] >= 1 and conn['fin_count'] == 0:
            open_connections += 1

        packets = conn['packets_src_to_dst'] + conn['packets_dst_to_src']
        packet_counts.append(packets)
        if conn['window_sizes']:
            window_sizes.extend(conn['window_sizes'])
        if conn['rtt_times']:
            rtt_times.extend(conn['rtt_times'])

    min_duration = min(durations, default=0)
    max_duration = max(durations, default=0)
    mean_duration = total_duration / complete_connections if complete_connections else 0

    min_rtt = min(rtt_times, default=0)
    max_rtt = max(rtt_times, default=0)
    mean_rtt = sum(rtt_times) / len(rtt_times) if rtt_times else 0

    min_packets = min(packet_counts, default=0)
    max_packets = max(packet_counts, default=0)
    mean_packets = sum(packet_counts) / len(packet_counts) if packet_counts else 0

    min_window_size = min(window_sizes, default=0)
    max_window_size = max(window_sizes, default=0)
    mean_window_size = sum(window_sizes) / len(window_sizes) if window_sizes else 0

    return {
        'total_connections': len(connections),
        'complete_connections': complete_connections,
        'reset_connections': reset_connections,
        'open_connections': open_connections,
        'before_capture_connections': before_capture_connections,
        'min_duration': min_duration,
        'mean_duration': mean_duration,
        'max_duration': max_duration,
        'min_rtt': min_rtt,
        'mean_rtt': mean_rtt,
        'max_rtt': max_rtt,
        'min_packets': min_packets,
        'mean_packets': mean_packets,
        'max_packets': max_packets,
        'min_window_size': min_window_size,
        'mean_window_size': mean_window_size,
        'max_window_size': max_window_size
    }

def output_format(connections):
    stats = calculate_statistics(connections)
    
    print("A) Total number of connections:", stats['total_connections'])
    print("________________________________________________")
    
    print("\nB) Connection's details\n")
    for i, (conn, details) in enumerate(connections.items(), 1):
        src, dst = conn
        print(f"Connection {i}:")
        print(f"Source Address: {src[0]}")
        print(f"Destination Address: {dst[0]}")
        print(f"Source Port: {src[1]}")
        print(f"Destination Port: {dst[1]}")
        print(f"Status: {determine_state(details)}")
        
        start_time = details.get('start_time', 0.0) or 0.0
        end_time = details.get('end_time', start_time) or start_time
        duration = end_time - start_time
        print(f"Start time: {start_time} seconds")
        print(f"End Time: {end_time} seconds")
        print(f"Duration: {duration} seconds")
        
        packets_src_to_dst = details['packets_src_to_dst']
        packets_dst_to_src = details['packets_dst_to_src']
        bytes_src_to_dst = details['bytes_src_to_dst']
        bytes_dst_to_src = details['bytes_dst_to_src']
        print(f"Number of packets sent from Source to Destination: {packets_src_to_dst}")
        print(f"Number of packets sent from Destination to Source: {packets_dst_to_src}")
        print(f"Total number of packets: {packets_src_to_dst + packets_dst_to_src}")
        print(f"Number of data bytes sent from Source to Destination: {bytes_src_to_dst}")
        print(f"Number of data bytes sent from Destination to Source: {bytes_dst_to_src}")
        print(f"Total number of data bytes: {bytes_src_to_dst + bytes_dst_to_src}")
        print("END\n++++++++++++++++++++++++++++++++")

    print("\nC) General\n")
    print("Total number of complete TCP connections:", stats['complete_connections'])
    print("Number of reset TCP connections:", stats['reset_connections'])
    print("Number of TCP connections that were still open when the trace capture ended:", stats['open_connections'])
    print("________________________________________________")
    
    print("\nD) Complete TCP connections\n")
    print(f"Minimum time duration: {stats['min_duration']} seconds")
    print(f"Mean time duration: {stats['mean_duration']} seconds")
    print(f"Maximum time duration: {stats['max_duration']} seconds")
    
    print("\nMinimum RTT value: ", stats['min_rtt'])
    print("Mean RTT value: ", stats['mean_rtt'])
    print("Maximum RTT value: ", stats['max_rtt'])
    
    print("\nMinimum number of packets including both directions: ", stats['min_packets'])
    print("Mean number of packets including both directions: ", stats['mean_packets'])
    print("Maximum number of packets including both directions: ", stats['max_packets'])
    
    print("\nMinimum receive window size including both directions: ", stats['min_window_size'])
    print("Mean receive window size including both directions: ", stats['mean_window_size'])
    print("Maximum receive window size including both directions: ", stats['max_window_size'])

def main():
    pcap_file = 'path_to_your_file.pcap'
    connections = parse_pcap(pcap_file)
    output_format(connections)

if __name__ == "__main__":
    main()
