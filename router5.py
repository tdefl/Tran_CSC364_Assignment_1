import socket
import sys
import traceback
from threading import Thread

# Router 2 acts as both a server and client, it must be able to send (forward to next hop), or act as the final destination. 
# Helper Functions

# The purpose of this function is to set up a socket connection.
def create_socket(host, port):
    # 1. Create a socket.
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 2. Try connecting the socket to the host and port.
    try:
        soc.connect((host, port))
    except:
        print("Connection Error to", port)
        sys.exit()
    # 3. Return the connected socket.
    return soc

# should be same as router1
# The purpose of this function is to read in a CSV file.
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
    print("Router 2 FIB: ", forwarding_dict)
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
            # ngl maybe a list implementation wouldve been simpler.
            netmask = details['netmask']
            print("netmask: " , netmask)
            network_dst_bin = ip_to_bin(network_dst)
            netmask_bin = ip_to_bin(netmask)
            print("Network dst int: ", network_dst)
            print("Network Dst binary: ", network_dst_bin)
            print("Netmask bin: ", netmask_bin)
            
            # Calculate the IP range
            ip_range = find_ip_range(network_dst_bin, netmask_bin)

            # Store the range along with the other details in the new table
            # this maps the original FIB network dst with a subdictionary containing min/max ip, gateway, and interface. 
            new_table[network_dst] = {
                'min_ip': ip_range[0],
                'max_ip': ip_range[1],
                'gateway': details['gateway'],
                'interface': details['interface']
            }
    print("Forwarding Table with Range: " , new_table, "\n\n\n")
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
    ip_int = int(ip_bin_string, 2) # binary string to integer conversion

    # 10. Return the binary representation of this int. (this formats it as 0bxxxxxxxx...)
    ip_bin = bin(ip_int)
    return ip_bin

# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.

def find_ip_range(network_dst_bin, netmask_bin):

    network_dst_int = int(network_dst_bin, 2)
    netmask_int = int(netmask_bin, 2)

    # Perform a bitwise AND to get the minimum IP
    min_ip = network_dst_int & netmask_int

    # 2. Perform a bitwise NOT on the netmask
    # to get the number of total IPs in this range.
    # Because the built-in bitwise NOT or compliment operator (~) works with signed ints,
    # we need to create our own bitwise NOT operator for our unsigned int (a netmask).

    # Perform a bitwise NOT on the netmask and add to the minimum IP to get the maximum IP
    compliment = bit_not(netmask_int, numbits=32)
    max_ip = min_ip + compliment

    print("\n\nUsing integer addition: min_ip + complement, max ip is: ", max_ip , "\n\n")
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
    
    # 3. Append the packet to received_by_router_5.txt.
    write_to_file('./output/received_by_router_5.txt', decoded_packet)
    # print("received packet", decoded_packet)
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
# (c) receive and process incoming packets,
# (d) forward them on, if needed.
def start_server():
    # 1. Create a socket.
    host = '127.0.0.1'
    port = 8005
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")
    
    try:
        # 2. Try binding the socket to the appropriate host and receiving port (based on the network topology diagram).
        try:
            soc.bind((host, port)) # bind so it can act as a server and listen
        except:
            print("Bind failed. Error : " + str(sys.exc_info()))
            sys.exit()

        
        # 3. Set the socket to listen. https://stackoverflow.com/questions/2444459/python-sock-listen
        soc.listen(5)

        print("Socket now listening")

        # 4. Read in and store the forwarding table.
        forwarding_table_path = "input/router_5_table.csv"
        forwarding_table = read_forwarding_table(forwarding_table_path)

        # 5. Store the default gateway port.
        default_gateway_port = find_default_gateway(forwarding_table)
        print("Default gateway port stored: ", default_gateway_port, "\n\n")
        # 6. Generate a new forwarding table that includes the IP ranges for matching against destination IPS.
        print("Call generate_forwarding_table_with_range")
        forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)
        
        # 7. Continuously process incoming packets.
        while True:
            # 8. Accept the connection.
            connection, address = soc.accept()
            
            ip, port = address
            print("Connected with " + str(ip) + ":" + str(port))
            # 9. Start a new thread for receiving and processing the incoming packets.
            try:
                thread = Thread(target=processing_thread, args=(connection, ip, port, forwarding_table_with_range, default_gateway_port))
                thread.start()
            except:
                print("Thread did not start.")
                traceback.print_exc()
    finally:
        soc.close()
        print("Server socket closed by Router 5")

# The purpose of this function is to receive and process incoming packets.
def processing_thread(connection, ip, port, forwarding_table_with_range, default_gateway_port, max_buffer_size=5120):
    # 1. Connect to the appropriate sending ports (based on the network topology diagram).
    
    # router 3 wont need to send to R4
    # 2. Continuously process incoming packets
    while True:
        # 3. Receive the incoming packet, process it, and store its list representation
        # packet = connection.recv(max_buffer_size).decode().strip()
        packet = receive_packet(connection, max_buffer_size)
        # 4. If the packet is empty (Router 1 has finished sending all packets), break out of the processing loop
        if not packet:
            print("No more packets recevied. Router 1 has finished sending")
            break
       
#           # 7. Store the source IP, destination IP, payload, and TTL.
            #     sourceIP        = packet["source_ip"]
            #     destination_ip   = packet["destination_ip"]
            #     payload         = packet["payload"]
            #     ttl             = packet["ttl"]

        # hmmm
        # 5. Store the source IP, destination IP, payload, and TTL.
        # packet_details = packet.split(",")
        # sourceIP = packet_details[0]
        # destinationIP = packet_details[1]
        # payload = packet_details[2]
        # ttl = int(packet_details[3])
        
        sourceIP = packet['source_ip']
        destinationIP = packet['destination_ip']
        payload = packet['payload']
        ttl = packet['ttl']

        # 6. Decrement the TTL by 1 and construct a new packet with the new TTL.
        new_ttl = ttl - 1
        new_packet = f"{sourceIP},{destinationIP},{payload},{new_ttl}"
        print("\nNew packet constructed with updated ttl: ", new_packet)

        # 7. Convert the destination IP into an integer for comparison purposes.
       # 9. Convert the destination IP into an integer for comparison purposes.
        destination_ip_bin = ip_to_bin(destinationIP)
        destination_ip_int = int(destination_ip_bin, 2)
        

        # 9. Find the appropriate sending port to forward this new packet to.
        sending_port = default_gateway_port
        
        # Check which range it falls into, and decide what port to send to.
        for ip_dst, details in forwarding_table_with_range.items():
            # if new_ttl <= 0:
            # write_to_file('./output/discarded_by_router_5.txt', new_packet)
            # print("DISCARD: ", new_packet)
            # if details['min_ip'] <= destination_ip_bin and destination_ip_bin <= details['max_ip']:
            if details['min_ip'] <= destination_ip_int and destination_ip_int <= details['max_ip']:
                print(f"\n\nChecking packet destination: {destinationIP}, converted into {destination_ip_int} against range {details['min_ip']} - {details['max_ip']} \n\n")
                sending_port = details['interface']
                print("interface found, sending to: ", sending_port)
                break # so not including breaks was the issue, because router 1 would just iterate thru the entire FIB even if a match was already found.
            # 10. If no port is found, then set the sending port to the default port.
            # else:
            #     print("sending to default gateway port")
            #     sending_port = default_gateway_port
            #     break
            

    

        # 11. Either
        # (a) send the new packet to the appropriate port (and append it to sent_by_router_5.txt),
        # (b) append the payload to out_router_5.txt without forwarding because this router is the last hop, or
        # (c) append the new packet to discarded_by_router_5.txt and do not forward the new packet
        # if sending_port == 'd' and new_ttl > 0:
        #     print("Sending packet", new_packet, "to Router 3")
        #     router5_socket.sendall(new_packet.encode())
        #     write_to_file('./output/sent_by_router_5.txt', new_packet, sending_port)
        
        # elif sending_port == '8006' and new_ttl > 0:  # Router 4's interface
        #     print("Sending packet", new_packet, "to Router 4")
        #     router6_socket.sendall(new_packet.encode())

        #     write_to_file('./output/sent_by_router_5.txt', new_packet, sending_port)
        # elif sending_port == 'a' and new_ttl > 0:
        #     # send back to R1
        #     connection.sendall(new_packet.encode())
        #     print("R2 send packet to R1")
        #     write_to_file('./output/sent_by_router_5.txt', new_packet, "a")

        if sending_port == "127.0.0.1":  # If this is the final destination
            print("OUT:", payload)
            write_to_file('./output/out_router_5.txt', payload)
        
        else:  # If it doesn't match any, entries in FIB
            print("DISCARD:", new_packet)
            write_to_file('./output/discarded_by_router_5.txt', new_packet)
    
    
    # router5_socket.close()
    # router6_socket.close()
    connection.close()
    print("Connections closed by router 5")

# Main Program
# 1. Start the server.
if __name__ == "__main__":  
    start_server()
