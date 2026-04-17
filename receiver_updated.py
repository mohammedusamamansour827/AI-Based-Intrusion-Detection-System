import socket
import os

SERVER_IP = '0.0.0.0'  # Listen on all network interfaces
PORT = 5001
BUFFER_SIZE = 4096
# Define HOSTS_DIR relative to the location of this script
# Assuming this script runs from /home/ubuntu, and the web app is in /home/ubuntu/model_files/Elhls/suricata_web/
HOSTS_DIR = '/home/ubuntu/model_files/Elhls/suricata_web/hosts' 
BASE_FILENAME = 'eve.json' # Base name for the received file

print("[Receiver] Starting server...")

# Create the hosts directory if it doesn't exist
try:
    os.makedirs(HOSTS_DIR, exist_ok=True)
    print(f"[Receiver] Ensured directory '{HOSTS_DIR}' exists.")
except OSError as e:
    print(f"[Receiver] ERROR creating directory '{HOSTS_DIR}': {e}")
    exit(1)

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Set socket option to reuse address
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((SERVER_IP, PORT))
        server_socket.listen(5) # Allow a backlog of connections
        print(f"[Receiver] Listening on port {PORT}...")

        while True: # Keep listening for new connections
            print("[Receiver] Waiting for a connection...")
            conn, addr = server_socket.accept()
            client_ip = addr[0]
            print(f"[Receiver] Connection from {addr}")

            # Construct the output filename using the client's IP
            # Replace dots in IP with underscores for safer filenames
            safe_client_ip = client_ip.replace('.', '_')
            output_filename = f"{safe_client_ip}_{BASE_FILENAME}"
            output_filepath = os.path.join(HOSTS_DIR, output_filename)

            try:
                with open(output_filepath, 'ab') as f:  # append mode
                    print(f"[Receiver] Receiving file and saving to {output_filepath}...")
                    while True:
                        data = conn.recv(BUFFER_SIZE)
                        if not data:
                            break
                        f.write(data)
                print(f"[Receiver] File received successfully from {client_ip} and saved as {output_filepath}.")
            except Exception as e:
                print(f"[Receiver] ERROR handling connection from {client_ip}: {e}")
            finally:
                conn.close()
                print(f"[Receiver] Connection from {client_ip} closed.")

except socket.error as e:
    print(f"[Receiver] Socket Error: {e}")
except Exception as e:
    print(f"[Receiver] SERVER ERROR: {e}")
finally:
    print("[Receiver] Server shutting down.")

