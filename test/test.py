dictionary = {"hello": 1, "world": 2}


print(str(dictionary))


ip = "163.120.179.133"



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

        print("octet: ", octet)
        print("int_octet: ", int_octet)
        # 5. convert the decimal int to binary,
        bin_octet = bin(int_octet)
        print("bin_octet: " , bin_octet)
        # 6. convert the binary to string and remove the "0b" at the beginning of the string,
        bin_octet_string = bin_octet[2:] # truncate the leftmost 2 bits using string array notation
        print("binoctetstring after truncation: " , bin_octet_string)
        print("length of binoctetstring after truncation: " , len(bin_octet_string))

        # 7. while the sting representation of the binary is not 8 chars long,
        # then add 0s to the beginning of the string until it is 8 chars long
        # (needs to be an octet because we're working with IP addresses).
        while len(bin_octet_string) < 8:
            print("padding with 0s")
            bin_octet_string = "0" + bin_octet_string
        print("Bin_octet_string after padding: ", bin_octet_string)
        # 8. Finally, append the octet to ip_bin_string.
        ip_bin_string += bin_octet_string
        print("Ip bin string: " , ip_bin_string)
    # 9. Once the entire string version of the binary IP is created, convert it into an actual binary int.
    ip_int = int(ip_bin_string, 2) # base 2 -> base 10
    print("Ip: ", ip, "To ip_int: " , ip_int)

    print("Returning this bin representation: ", bin(ip_int))
    print("Data type: ", type(bin(ip_int)))

    print("6969" + bin(ip_int))
    # 10. Return the binary representation of this int.
    return bin(ip_int)
    # return ip_int

# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n 

# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.
def find_ip_range(network_dst_bin, netmask_bin):
    # Perform a bitwise AND to get the minimum IP
    min_ip = network_dst_bin & netmask_bin

    # Perform a bitwise NOT on the netmask and add to the minimum IP to get the maximum IP
    compliment = bit_not(netmask_bin, numbits=32)
    max_ip = min_ip | compliment

    # return a tuple for min, max
    print("Min ip: " , min_ip)
    print("Max ip: " , max_ip)
    return [min_ip, max_ip]


# 10.0.0.200 = 00001010 00000000 00000000 11001000
# 255.255.255.192 = 11111111 11111111 11111111 11000000

ip_to_bin("10.0.0.200")

# if "00001010000000000000000011001000" == ip_to_bin("10.0.0.200"):
#     print("true")


# if "11111111111111111111111111000000" == ip_to_bin("255.255.255.192"):
#     print("true")


