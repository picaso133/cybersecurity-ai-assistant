import paramiko
import time
import random
import socket

HONEYPOT_IP = '127.0.0.1'
HONEYPOT_PORT = 2222
VALID_MAC_ADDRESS = '00:1A:2B:3C:4D:5E'
WHITELISTED_MAC_ADDRESSES = ['00:1A:2B:3C:4D:5E', '00:1A:2B:3C:4D:5F']
NON_WHITELISTED_MAC_ADDRESSES = ['00:1A:2B:3C:4D:60', '00:1A:2B:3C:4D:61']

def simulate_unsuccessful_auth_attempts(ip, port, attempts):
    for _ in range(attempts):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port, username='invalid_user', password='invalid_pass')
        except paramiko.AuthenticationException:
            print("Unsuccessful authentication attempt")
        finally:
            client.close()
        time.sleep(random.uniform(0.1, 0.5))

def simulate_successful_auth(ip, port, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port, username=username, password=password)
        print("Successful authentication attempt")
    except paramiko.AuthenticationException:
        print("Authentication failed")
    finally:
        client.close()

def simulate_network_activity(mac_address):
    if mac_address in WHITELISTED_MAC_ADDRESSES:
        print(f"Network activity from whitelisted MAC address: {mac_address}")
    else:
        print(f"Network activity from non-whitelisted MAC address: {mac_address}")

# if __name__ == "__main__":
#     # Simulate too many unsuccessful authentication attempts
#     simulate_unsuccessful_auth_attempts(HONEYPOT_IP, HONEYPOT_PORT, 10)

#     # Simulate first successful authentication attempt from a valid MAC address
#     simulate_successful_auth(HONEYPOT_IP, HONEYPOT_PORT, 'valid_user', 'valid_pass')

#     # Simulate network activity from whitelisted MAC address
#     for mac in WHITELISTED_MAC_ADDRESSES:
#         simulate_network_activity(mac)

#     # Simulate network activity from non-whitelisted MAC addresses
#     for mac in NON_WHITELISTED_MAC_ADDRESSES:
#         simulate_network_activity(mac)