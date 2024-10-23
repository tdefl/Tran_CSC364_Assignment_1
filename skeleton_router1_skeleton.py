import socket
import sys
import time
import os
import glob

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


# # The purpose of this function is to read in a CSV file.
# def read_csv(path):
#     # 1. Open the file for reading.
#     table_file = open(path, "r")
#     # 2. Store each line.
#     table = table_file.readlines()
#     # 3. Create an empty list to store each processed row.
#     table_list = []

#     # 4. For each line in the file:
#     # FIB allows routers to do fast lookup, so I'll use a dictionary for better lookup times than a list of lists
#     # for line in table:
#     #     # split it into a list of strings by the delimiter using .split(","), 
#     #     # remove any leading/trailing spaces using strip(), and append resulting list to table_list
#     #     parsed_line = [element.strip() for element in line.strip().split(",")]
#     #     table_list.append(parsed_line)

#     # i guess i've now used this to specifically read a forwarding table. 
#     forwarding_dict = {}
#     for line in table:
#         network_dst, netmask, gateway, interface = [element.strip() for element in line.strip().split(",")]

#         # store parsed data in a dictionary of dictionaries. 
#         # forwarding_dict[network_dst] = [
#         #     netmask, gateway, interface
#         # ]
#         forwarding_dict[network_dst] = {
#             'netmask' : netmask,
#             'gateway' : gateway,
#             'interface' : interface
#         }
#         # { network_dst : [netmask, gateway, interface]}

#     # Close the csv file and return the parsed forwarding table.
#     table_file.close()
#     return forwarding_dict


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
   
    # for line in table:
    #     # split it into a list of strings by the delimiter using .split(","), 
    #     # remove any leading/trailing spaces using strip(), and append resulting list to table_list

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
#def generate_forwarding_table_with_range(table):
    # 1. Create an empty list to store the new forwarding table.
    new_table = []
    # 2. Traverse the old forwarding table, row by row,
    ## for ...:
        # 3. and process each network destination other than 0.0.0.0
        # (0.0.0.0 is only useful for finding the default port).
        ## if ...:
            # 4. Store the network destination and netmask.
            ## network_dst_string = ...
            ## netmask_string = ...
            # 5. Convert both strings into their binary representations.
            ## network_dst_bin = ...
            ## netmask_bin = ...
            # 6. Find the IP range.
            ## ip_range = ...
            # 7. Build the new row.
            ## new_row = ...
            # 8. Append the new row to new_table.
            ## new_table.append(new_row)
    # 9. Return new_table.
    return new_table

# hmm...
# generates a new forwarding table from the old one, with the additional inclusion of ip range.
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
    return bin(ip_int)


# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.
# def find_ip_range(network_dst, netmask):
#     # 1. Perform a bitwise AND on the network destination and netmask
#     # to get the minimum IP address in the range.
#     ## bitwise_and = ...
#     # 2. Perform a bitwise NOT on the netmask
#     # to get the number of total IPs in this range.
#     # Because the built-in bitwise NOT or compliment operator (~) works with signed ints,
#     # we need to create our own bitwise NOT operator for our unsigned int (a netmask).
#     ## compliment = ...
#     ## min_ip = ...
#     # 3. Add the total number of IPs to the minimum IP
#     # to get the maximum IP address in the range.
#     ## max_ip = ...
#     # 4. Return a list containing the minimum and maximum IP in the range.


#     return [min_ip, max_ip]


def find_ip_range(network_dst_bin, netmask_bin):
    # Perform a bitwise AND to get the minimum IP
    min_ip = network_dst_bin & netmask_bin

    # Perform a bitwise NOT on the netmask and add to the minimum IP to get the maximum IP
    compliment = bit_not(netmask_bin, numbits=32)
    max_ip = min_ip | compliment

    return [min_ip, max_ip]


# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n


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


# Main Program

# 0. Remove any output files in the output directory
# (this just prevents you from having to manually delete the output files before each run).
files = glob.glob('./output/*')
for f in files:
    os.remove(f)

# 1. Connect to the appropriate sending ports (based on the network topology diagram).
## ...
## ...

# 2. Read in and store the forwarding table.
inputs_dir = "input"
FIB_filename = "router_1_table.csv"
forwarding_table_path = os.path.join(inputs_dir, FIB_filename)

forwarding_table = read_forwarding_table(forwarding_table_path)
print(forwarding_table)
# 3. Store the default gateway port.
## default_gateway_port = ...
# 4. Generate a new forwarding table that includes the IP ranges for matching against destination IPS.
## forwarding_table_with_range = ...

# 5. Read in and store the packets.
## packets_table = ...

# 6. For each packet,
## for ...:
    # 7. Store the source IP, destination IP, payload, and TTL.
    ## sourceIP = ...
    ## destinationIP = ...
    ## payload = ...
    ## ttl = ...

    # 8. Decrement the TTL by 1 and construct a new packet with the new TTL.
    ## new_ttl = ...
    ## new_packet = ...

    # 9. Convert the destination IP into an integer for comparison purposes.
    ## destinationIP_bin = ...
    ## destinationIP_int = ...

    # 9. Find the appropriate sending port to forward this new packet to.
    ## ...

    # 10. If no port is found, then set the sending port to the default port.
    ## ...

    # 11. Either
    # (a) send the new packet to the appropriate port (and append it to sent_by_router_1.txt),
    # (b) append the payload to out_router_1.txt without forwarding because this router is the last hop, or
    # (c) append the new packet to discarded_by_router_1.txt and do not forward the new packet
    ## if ...:
    #     print("sending packet", new_packet, "to Router 2")
    #     ## ...
    # ## elif ...
    #     print("sending packet", new_packet, "to Router 4")
    #     ## ...
    # ## elif ...:
    #     print("OUT:", payload)
    #     ## ...
    # else:
    #     print("DISCARD:", new_packet)
    #     ## ...

    # # Sleep for some time before sending the next packet (for debugging purposes)
    # time.sleep(1)