import socket
import sys
import traceback

# The purpose of this function is to set up a server socket for Router 3.
def start_server():
    host = '127.0.0.1'
    port = 8003
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")

    try:
        soc.bind((host, port))
        soc.listen(5)
        print("Router 3 is listening on port", port)

        # Continuously process incoming packets.
        while True:
            connection, address = soc.accept()
            ip, port = address
            print("Connected with " + ip + ":" + str(port))
            try:
                handle_connection(connection)
            except Exception as e:
                print("Error processing connection:", e)
                traceback.print_exc()
            finally:
                connection.close()
                print("Connection closed by Router 3")
    except Exception as e:
        print("Server Error:", e)
    finally:
        soc.close()
        print("Router 3 socket closed")

# The purpose of this function is to handle the incoming connection and process the packet.
def handle_connection(connection, max_buffer_size=5120):
    try:
        received_packet = connection.recv(max_buffer_size)
        packet_size = sys.getsizeof(received_packet)

        if packet_size > max_buffer_size:
            print("The packet size is greater than expected", packet_size)

        decoded_packet = received_packet.decode('utf-8').strip()

        if not decoded_packet:
            print("No data received. Closing connection.")
            return

        print("Received packet:", decoded_packet)

        # Parse the packet
        packet_details = decoded_packet.split(",")
        source_ip = packet_details[0]
        destination_ip = packet_details[1]
        payload = packet_details[2]
        ttl = int(packet_details[3])

        # Log the payload to file (or any other processing needed).
        write_to_file('./output/out_router_3.txt', f"Source: {source_ip}, Payload: {payload}")

    except Exception as e:
        print("Error handling connection:", e)
        traceback.print_exc()

# The purpose of this function is to write the payload to a file.
def write_to_file(path, data):
    with open(path, "a") as out_file:
        out_file.write(data + "\n")

# Start Router 3
if __name__ == "__main__":
    start_server()
