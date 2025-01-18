import struct
import socket

def parse_pcap(file):
    connections = {}

    with open(file, 'rb') as f:
        f.read(24) #Skipping the global header because it's useless for our assignment
        start_time = None

        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
               break  #End of file
           
            #To get the neeeded information of the packet, timestamp in sec, millisec,
            #the packet data, and the original length 
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('=IIII', packet_header) 
            timestamp = ts_sec + ts_usec / 1_000_000 #adding up the secs and millisecs
            packet_data = f.read(incl_len)
            
            #Setting up time. 
            if start_time is None:
                start_time = timestamp
            relative_time = timestamp - start_time
            
            #Checking if the connection is IPv4. If not, then we skip
            eth_protocol = struct.unpack('!H', packet_data[12:14])[0]
            if eth_protocol != 0x0800:
                continue

            #Using the struct module to check if packet is TCP
            #by looking at the 8th byte of the patcket. If not, we skip
            ip_header = packet_data[14:34]
            ip_header_data = struct.unpack('!BBHHHBBH4s4s', ip_header)
            protocol = ip_header_data[6]
            if protocol != 6:
                continue

            #Assigning ip addresses from the ip header we unpacked earlier
            #Extracting the TCP header, and assigning the designated ports and flags required
            src_ip = socket.inet_ntoa(ip_header_data[8])
            dst_ip = socket.inet_ntoa(ip_header_data[9])
            tcp_header = packet_data[34:54]
            src_port, dst_port, seq, ack_seq, offset_reserved_flags = struct.unpack('!HHLLH', tcp_header[:14])
            flags = offset_reserved_flags & 0x3F

            syn_flag = (flags & 0x02) != 0
            fin_flag = (flags & 0x01) != 0
            rst_flag = (flags & 0x04) != 0
            ack_flag = (flags & 0x10) != 0


            #Assigning the source ip address and destination ip address 
            if (src_ip, src_port) < (dst_ip, dst_port):
                connection_key = (src_ip, src_port, dst_ip, dst_port)
                direction = 'src_to_dst'
            else:
                connection_key = (dst_ip, dst_port, src_ip, src_port)
                direction = 'dst_to_src'


            #Initializing the dictionary for the connections
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
                    'is_complete': False,
                    'unacknowledged': {}  # Store unacknowledged packets for RTT calculation
                }

            conn = connections[connection_key]

            #Update flags and timings
            if syn_flag:
                conn['syn_count'] += 1
                if conn['start_time'] is None:
                    conn['start_time'] = relative_time
            if fin_flag:
                conn['fin_count'] += 1
                conn['end_time'] = relative_time
            if rst_flag:
                conn['reset'] = True

            #Calculate RTT using the first matching ACK
            if direction == 'src_to_dst' and not ack_flag:
                conn['unacknowledged'][seq] = relative_time
                
            elif direction == 'dst_to_src' and ack_flag:
                #Check if this ACK corresponds to any previously unacknowledged packet
                for unack_seq, send_time in list(conn['unacknowledged'].items()):
                    if ack_seq >= unack_seq:
                        # Calculate RTT as time difference between packet sent and ACK received
                        rtt = relative_time - send_time
                        conn['rtt_times'].append(rtt)
                        del conn['unacknowledged'][unack_seq]
                        break

            if conn['syn_count'] >= 1 and conn['fin_count'] >= 1:
                conn['is_complete'] = True

            #Accurate packet and byte counts
            if direction == 'src_to_dst':
                conn['packets_src_to_dst'] += 1
                conn['bytes_src_to_dst'] += (incl_len - 54)
            else:
                conn['packets_dst_to_src'] += 1
                conn['bytes_dst_to_src'] += (incl_len - 54)

            #Include zero window sizes
            window_size = struct.unpack('!H', tcp_header[14:16])[0]
            conn['window_sizes'].append(window_size)

    return connections

def calculate_statistics(connections):
    total_duration = 0
    complete_connections = 0
    reset_connections = 0
    open_connections = 0
    durations = []
    packet_counts = []
    window_sizes = []
    rtt_times = []

    #Analyze each connection to get the required values
    for conn in connections.values():
        if conn['reset']:
            reset_connections += 1

        if conn['is_complete']:
            complete_connections += 1
            
            #Calculating the total time spent for the connection
            if conn['start_time'] is not None and conn['end_time'] is not None:
                duration = conn['end_time'] - conn['start_time']
                durations.append(duration)
                total_duration += duration

            #Getting the amount of packets
            packets = conn['packets_src_to_dst'] + conn['packets_dst_to_src']
            packet_counts.append(packets)
            
            #Getting the window size
            window_sizes.extend(conn['window_sizes'])
            
        #Getting the open connections left
        elif conn['syn_count'] >= 1 and conn['fin_count'] == 0:
            open_connections += 1
            
        #Getting the RTT values
        rtt_times.extend(conn['rtt_times'])
        

    #Calculating and storing all the measurements got from the connection
    min_duration = min(durations)
    max_duration = max(durations)
    mean_duration = total_duration / complete_connections if complete_connections else 0

    min_rtt = min(rtt_times)
    max_rtt = max(rtt_times)
    mean_rtt = sum(rtt_times) / len(rtt_times) if rtt_times else 0

    min_packets = min(packet_counts)
    max_packets = max(packet_counts)
    mean_packets = sum(packet_counts) / len(packet_counts) if packet_counts else 0

    min_window_size = min(window_sizes)
    max_window_size = max(window_sizes)
    mean_window_size = sum(window_sizes) / len(window_sizes) if window_sizes else 0

    return {
        'total_connections': len(connections),
        'complete_connections': complete_connections,
        'reset_connections': reset_connections,
        'open_connections': open_connections,
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


#Printing the output using the required output format
def output_format(connections):
    stats = calculate_statistics(connections)
    
    print("A) Total number of connections:", stats['total_connections'])
    print("________________________________________________")
    
    print("\nB) Connection's details\n")
    for i, (conn, details) in enumerate(connections.items(), 1):
        src_ip, src_port, dst_ip, dst_port = conn
        print(f"Connection {i}:")
        print(f"Source Address: {src_ip}")
        print(f"Destination Address: {dst_ip}")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")
        
        start_time = details.get('start_time', 0.0) or 0.0
        end_time = details.get('end_time', start_time) or start_time
        duration = end_time - start_time
        
        syn_count = details['syn_count']
        fin_count = details['fin_count']
        status = f"S{syn_count}F{fin_count}"
        
        print(f"Status: {status}")
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
    print(f"\nMinimum RTT value: {stats['min_rtt']}")
    print(f"Mean RTT value: {stats['mean_rtt']}")
    print(f"Maximum RTT value: {stats['max_rtt']}")
    print(f"\nMinimum number of packets including both send/received: {stats['min_packets']}")
    print(f"Mean number of packets including both send/received: {stats['mean_packets']}")
    print(f"Maximum number of packets including both send/received: {stats['max_packets']}")
    print(f"\nMinimum receive window size including both send/received: {stats['min_window_size']} bytes")
    print(f"Mean receive window size including both send/received: {stats['mean_window_size']} bytes")
    print(f"Maximum receive window size including both send/received: {stats['max_window_size']} bytes")

def main():
    file = 'replace_file_path'  # Replace with the actual file path
    connections = parse_pcap(file)
    output_format(connections)

if __name__ == "__main__":
    main()
