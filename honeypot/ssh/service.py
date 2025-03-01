#!/usr/bin/env python3

import socket
import threading
import paramiko
import datetime
import logging
import os
from elasticsearch import Elasticsearch
from datetime import UTC
import signal

# Configure logging
log_timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
log_filename = f"ssh_honeypot_{log_timestamp}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename=log_filename
)
print(f"SSH Honeypot starting at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Logging to: {log_filename}")
logger = logging.getLogger("ssh-honeypot")

# Elasticsearch configuration
ES_CLOUD_ID = "***"
ES_API_KEY = "***"
ES_INDEX = "ssh-honeypot"


class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        
    def check_auth_password(self, username, password):
        # Log the authentication attempt
        log_data = {
            "timestamp": datetime.datetime.now(UTC).isoformat(),
            "source_ip": self.client_ip,
            "username": username,
            "password": password,
            "event_type": "auth_attempt"
        }
        
        logger.info(f"Authentication attempt: {self.client_ip} - {username}:{password}")
        send_to_elasticsearch(log_data)
        
        # Always reject authentication
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"
    
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def send_to_elasticsearch(log_data):
    """Send log data to Elasticsearch"""
    try:
        es = Elasticsearch(
            cloud_id=ES_CLOUD_ID,
            api_key=ES_API_KEY,
            request_timeout=10
        )
        es.index(index=ES_INDEX, document=log_data)
        logger.info("Log sent to Elasticsearch")
    except Exception as e:
        logger.error(f"Failed to send log to Elasticsearch: {e}")

def handle_connection(client_socket, client_address):
    """Handle incoming SSH connection"""
    client_ip = client_address[0]
    client_port = client_address[1]
    
    # Log connection attempt
    log_data = {
        "timestamp": datetime.datetime.now(UTC).isoformat(),
        "source_ip": client_ip,
        "source_port": client_port,
        "event_type": "connection"
    }
    
    logger.info(f"Connection from: {client_ip}:{client_port}")
    send_to_elasticsearch(log_data)
    
    try:
        # Set up SSH server
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(paramiko.RSAKey(filename="server_key"))
        
        # Start the SSH server
        server = SSHServer(client_ip)
        transport.start_server(server=server)
        
        # Wait for authentication
        channel = transport.accept(20)
        if channel is None:
            logger.info(f"No channel from {client_ip}:{client_port}")
            return
        
        server.event.wait(10)
        
    except Exception as e:
        logger.error(f"Error handling SSH connection: {e}")
    finally:
        try:
            transport.close()
        except:
            pass
        client_socket.close()

def generate_ssh_key():
    """Generate SSH key if it doesn't exist"""
    if not os.path.exists("server_key"):
        logger.info("Generating new SSH key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file("server_key")

def start_honeypot(port=2222):  # Use port 22 in production
    """Start the SSH honeypot server"""
    generate_ssh_key()
    
    # Create socket and listen for connections
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Set socket timeout to ensure periodic checks for shutdown signal
    sock.settimeout(1.0)
    
    # Flag to control the main loop
    running = True
    
    def signal_handler(sig, frame):
        nonlocal running
        running = False
        logger.info("Received shutdown signal")
        print("\nShutting down SSH Honeypot...")
        
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        sock.bind(("0.0.0.0", port))
        sock.listen(100)
        
        logger.info(f"SSH Honeypot listening on port {port}")
        print(f"SSH Honeypot started on port {port} (Press Ctrl+C to stop)")
        
        while running:
            try:
                client, addr = sock.accept()
                thread = threading.Thread(target=handle_connection, args=(client, addr))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue  # Just loop back to check if we should still be running
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                if running:  # Only log if we're not shutting down
                    continue
                else:
                    break
                    
    except Exception as e:
        logger.error(f"Error starting SSH honeypot: {e}")
    finally:
        logger.info("SSH Honeypot shutting down")
        print("SSH Honeypot shutdown complete")
        sock.close()

if __name__ == "__main__":
    logger.info("Starting SSH honeypot")
    start_honeypot()