# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.

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


# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n

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

    ## compliment = ...
    ## min_ip = ...

   

    # 00001010 00000000 00000000 11000000 = 10.0.0.192
    # So the IP range of this row starts at 10.0.0.192.
    # To answer 2) we take the bitwise NOT (i.e., compliment) of the netmask:
    # 11111111 11111111 11111111 11000000 = 255.255.255.192
    # ------------------------------------------------------
    # 00000000 00000000 00000000 00111111 = 63
    # So the last range of the IP is 10.0.0.192 + 63 = 10.0.0.255. So the entire IP range is 
    # [10.0.0.192 - 10.0.0.255]. 
    # We can therefore rewrite this row with only the relevant information needed by the router:

    # max_ip = min_ip | compliment

    # # return a tuple for min, max;
    # print("Using min_ip | complement, max ip is: ", max_ip)
  


    
    max_ip = min_ip + compliment
    print("\n\nUsing integer addition: min_ip + complement, max ip is: ", max_ip )
    return [min_ip, max_ip]


 # 10.0.0.200 = 00001010 00000000 00000000 11001000
    # 255.255.255.192 =

actual_dst_bin = "0b1010000000000000000011001000"
network_dst_bin = ip_to_bin("10.0.0.200")
print("Network dst bin: ", network_dst_bin)
print(actual_dst_bin == network_dst_bin)



actual_netmask_bin = "0b11111111111111111111111111000000"
netmask_bin = ip_to_bin("255.255.255.192")
print("netmask bin: ", netmask_bin)
print(actual_netmask_bin == netmask_bin)


netmask_compliment = bit_not(int(netmask_bin, 2))

print(netmask_compliment)

# know that max is 10.0.0.255
actual_max_ip = int(ip_to_bin("10.0.0.255"), 2)


min_ip, max_ip = find_ip_range(network_dst_bin, netmask_bin)

print("min ip: ", min_ip)
print("Max ip: ", max_ip)

print("actual max ip: " , actual_max_ip)
print(max_ip==actual_max_ip)