import socket
import sys
import traceback
from threading import Thread

def read_forwarding_table(path):
    # 1. Open the file for reading.
    table_file = open(path, "r")
    # 2. Store each line.
    table = table_file.readlines()
    # 3. Create an empty dictionary to store each processed row.
    forwarding_dict = {}
    
    # 4. For each line in the file:
    # FIB allows routers to do fast lookup, so I'll use a dictionary for better lookup times than a list of lists
    for line in table:
        network_dst, netmask, gateway, interface = [element.strip() for element in line.strip().split(",")]

        # store parsed data in a dictionary of dictionaries. 
        # forwarding_dict[network_dst] = [
        #     netmask, gateway, interface
        # ]
        forwarding_dict[network_dst] = {
            'netmask' : netmask,
            'gateway' : gateway,
            'interface' : interface
        }
        # { network_dst : [netmask, gateway, interface]}

    # Close the csv file and return the parsed forwarding table.
    table_file.close()
    return forwarding_dict

# another csv parsing function, but for packets.
def read_packets(path):
    packets = [] # an empty list to store dictionaries, each dictionary being a packet.

    with open(path, "r") as packet_file:

        for line in packet_file:
            source_ip, destination_ip, payload, ttl = [element.strip() for element in line.strip().split(",")]
            
            packets.append({
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'payload': payload,
                'ttl': int(ttl)
            })
    return packets

# The purpose of this function is to find the default port
# when no match is found in the forwarding table for a packet's destination IP.
def find_default_gateway(table):
    default_gateway = "0.0.0.0"
    # 1. Traverse the table, row by row,
    ## for ...:
    for network_dst, details in table.items():
        if network_dst == default_gateway:
            return details['interface'] # return the interface (MAC addr) of the gateway
    # if no default gateway found, return None
    return None

# The purpose of this function is to generate a forwarding table that includes the IP range for a given interface.
# In other words, this table will help the router answer the question:
# Given this packet's destination IP, which interface (i.e., port) should I send it out on?
def generate_forwarding_table_with_range(table):
    new_table = {}

    for network_dst, details in table.items():

        if network_dst != "0.0.0.0":  # Skip the default gateway

            netmask = details['netmask']
            network_dst_bin = ip_to_bin(network_dst)
            netmask_bin = ip_to_bin(netmask)

            # Calculate the IP range
            ip_range = find_ip_range(network_dst_bin, netmask_bin)

            # Store the range along with the other details in the new table
            new_table[network_dst] = {
                'min_ip': ip_range[0],
                'max_ip': ip_range[1],
                'gateway': details['gateway'],
                'interface': details['interface']
            }
    return new_table


# The purpose of this function is to convert a string IP to its binary representation.
def ip_to_bin(ip):
    # 1. Split the IP into octets.
    ip_octets = ip.split(".") # ip addr is written in octets delimited by "." (xxxx.xxxx.xxxx.xxxx)
    
    # 2. Create an empty string to store each binary octet.
    ip_bin_string = ""
    # 3. Traverse the IP, octet by octet,
    for octet in ip_octets:

         # 4. and convert the octet to an int,
        int_octet = int(octet)

        # 5. convert the decimal int to binary,
        bin_octet = bin(int_octet)

        # 6. convert the binary to string and remove the "0b" at the beginning of the string,
        bin_octet_string = bin_octet[2:] # truncate the leftmost 2 bits using string array notation

        # 7. while the sting representation of the binary is not 8 chars long,
        # then add 0s to the beginning of the string until it is 8 chars long
        # (needs to be an octet because we're working with IP addresses).
        while len(bin_octet_string) < 8:
            bin_octet_string = '0' + bin_octet_string
     
        # 8. Finally, append the octet to ip_bin_string.
        ip_bin_string += bin_octet_string

    # 9. Once the entire string version of the binary IP is created, convert it into an actual binary int.
    ip_int = int(ip_bin_string, 2) # base 2 integer.

    # 10. Return the binary representation of this int.
    return ip_int

# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.
def find_ip_range(network_dst_bin, netmask_bin):
    # Perform a bitwise AND to get the minimum IP
    min_ip = network_dst_bin & netmask_bin

    # Perform a bitwise NOT on the netmask and add to the minimum IP to get the maximum IP
    compliment = bit_not(netmask_bin, numbits=32)
    max_ip = min_ip | compliment

    # return a tuple for min, max
    return [min_ip, max_ip]

# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n


# The purpose of this function is to receive and process an incoming packet.
def receive_packet(connection, max_buffer_size):
    # 1. Receive the packet from the socket.
     
    received_packet = connection.recv(max_buffer_size)

    # 2. If the packet size is larger than the max_buffer_size, print a debugging message
    packet_size = sys.getsizeof(received_packet)
    if packet_size > max_buffer_size:
        print("The packet size is greater than expected", packet_size)

    # 3. Decode the packet and strip any trailing whitespace.
    decoded_packet = received_packet.decode('utf-8').strip()

    if not decoded_packet:
            return None
    
    # 3. Append the packet to received_by_router_2.txt.
    write_to_file('./output/received_by_router_5.txt', decoded_packet)
    print("received packet", decoded_packet)
    ## ...
    # 4. Split the packet by the delimiter.
    packet_details = decoded_packet.split(",")

    # 5. Return the list representation of the packet.
    return {
        'source_ip': packet_details[0],
        'destination_ip': packet_details[1],
        'payload': packet_details[2],
        'ttl': int(packet_details[3])
    }


# The purpose of this function is to write packets/payload to file.
def write_to_file(path, packet_to_write, send_to_router=None):
    # 1. Open the output file for appending.
    out_file = open(path, "a")
    # 2. If this router is not sending, then just append the packet to the output file.
    if send_to_router is None:
        out_file.write(packet_to_write + "\n")

    # 3. ELSE if this router is sending, then append the intended recipient, along with the packet, to the output file
    else:
        out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
    
    # 4. Close the output file after finished writing to it.
    out_file.close()



# The purpose of this function is to
# (a) create a server socket,
# (b) listen on a specific port,
# (c) receive and process incoming packets.
def start_server():
    # 1. Create a socket.
    host = '127.0.0.1'
    port = 8005 # Router 5
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")

    try:
        # 2. Try binding the socket to the appropriate host and receiving port.
        try:
            soc.bind((host, port))  # bind so it can act as a server and listen
        except:
            print("Bind failed. Error : " + str(sys.exc_info()))
            sys.exit()

        # 3. Set the socket to listen.
        soc.listen(5)
        print("Router 5 is now listening on port", port)

        # 4. Continuously process incoming packets.
        while True:
            # 5. Accept the connection.
            connection, address = soc.accept()
            
            ip, port = address
            print("Connected with " + ip + ":" + str(port))
            # 6. Handle the connection and process the packet.
            try:
                processing_thread(connection)
            except:
                print("Error processing connection.")
                traceback.print_exc()
            finally:
                connection.close()
                print("Connection closed by Router 5")
    finally:
        soc.close()
        print("Router 5 socket closed")

# The purpose of this function is to receive and process incoming packets.
def processing_thread(connection, max_buffer_size=5120):
    while True:
        # 1. Receive the incoming packet, process it, and store its list representation.
        packet = receive_packet(connection, max_buffer_size)
        
        # 2. If the packet is empty (no more data), break out of the processing loop.
        if not packet:
            print("No more packets received. Closing connection.")
            break
        
        # 3. Store the source IP, destination IP, payload, and TTL.
        source_ip = packet['source_ip']
        destination_ip = packet['destination_ip']
        payload = packet['payload']
        ttl = packet['ttl']

        # 4. Log the payload to file (or any other processing needed).
        write_to_file('./output/out_router_5.txt', f"Source: {source_ip}, Payload: {payload}")

# Main Program

# 1. Start Router 5's server.
if __name__ == "__main__":
    start_server()