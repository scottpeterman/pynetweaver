import json
import socket
from queue import Queue
from netmiko import ConnectHandler
from ttp import ttp
import logging
from netmiko import ConnectHandler
import paramiko

import paramiko

# Define comprehensive lists of cryptographic settings
all_inclusive_ciphers = [
    "aes256-ctr", "aes128-ctr",           # Strong, modern ciphers
    "aes256-cbc", "aes192-cbc", "aes128-cbc",  # CBC ciphers (for older devices)
    "3des-cbc"                             # Legacy cipher for compatibility
]

all_inclusive_kex = [
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",   # Modern elliptic curve key exchanges
    "diffie-hellman-group-exchange-sha256",                               # Modern DH key exchange
    "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"          # Legacy DH key exchanges for compatibility
]

all_inclusive_macs = [
    "hmac-sha2-512", "hmac-sha2-256",   # Modern, secure MACs
    "hmac-sha1", "hmac-md5"             # Legacy MACs for older devices
]

# Set global defaults for Paramiko
paramiko.Transport._preferred_ciphers = tuple(all_inclusive_ciphers)
paramiko.Transport._preferred_kex = tuple(all_inclusive_kex)
paramiko.Transport._preferred_macs = tuple(all_inclusive_macs)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLDPHandler:
    def __init__(self, vendor, exclude_string):
        """
        Initialize the LLDP handler with vendor type and exclusion criteria.

        :param vendor: Vendor type of the seed device (e.g., 'arista', 'aruba').
        :param exclude_string: Comma-separated string of devices to exclude.
        """
        self.vendor = vendor.lower()
        self.exclude = [s.strip() for s in exclude_string.split(',')]
        self.queue = Queue()
        self.visited = set()
        self.failed_neighbors = []
        self.network_map = {}

        # Define vendor-specific LLDP templates
        self.arista_template = '''Interface {{ local_port }} detected {{ num_peers }} LLDP neighbors:
    Chassis ID     : {{ chassis_id }}
    Port ID        : "{{ remote_port }}"
  - System Name: "{{ device_id | default('unknown') }}"
  - System Description: "{{ platform | ORPHRASE | default('unknown')}}"
    Management Address : {{ ip }}
        '''

        self.cisco_template = '''Local Intf: {{ local_port }}
Chassis id: {{ chassis_id }}
Port id: {{ remote_port }}
Port Description: {{ port_descr | ORPHRASE | default("no desc") }}
System Name: {{ device_id | default("unknown") }}
IP Address: {{ ip | default("unknown") }}
    IP: {{ ip }}              '''

        self.aruba_template = '''
  Local Port   : {{ local_port  | default("unknown")}}
  ChassisId    :  {{ chassis_id | default("unknown") }}      
  SysName      : {{ device_id | ORPHRASE | default("unknown") }}   
  System Descr : {{ platform | re(".*?") | default("no data") }}                     
  PortDescr    : {{ remote_port | ORPHRASE | default("PORT")}}      
     Address : {{ ip | default("unknown")}}
        '''

    def set_seed_device(self, seed_device):
        """Initialize with the seed device and set up the discovery queue."""
        self.seed_device = seed_device
        self.queue.put(seed_device)

    def is_excluded(self, device_id):
        """Check if a device ID matches any exclusion criteria."""
        for exclusion in self.exclude:
            if exclusion in device_id:
                logger.info(f"Excluding device based on rule: {device_id}")
                return True
        return False

    def is_port_open(self, ip, port, timeout=3):
        """Check if a specific port is open on the given IP address."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            return result == 0
        except socket.error:
            return False
        finally:
            sock.close()

    def fetch_neighbors(self, device):
        """Fetch neighbors using LLDP data for a given device."""
        device_type = 'arista_eos' if self.vendor == 'arista' else 'hp_procurve'
        cli_command = 'show lldp neig detail' if self.vendor == 'arista' else 'show lldp info remote-device detail'

        ttp_template = self.arista_template if self.vendor == 'arista' else self.aruba_template
        platform = device.get('platform','unknown')
        if 'cisco' in platform.lower():
            ttp_template = self.cisco_template

        required_keys = ['ip', 'username', 'password']
        for key in required_keys:
            if key not in device:
                if key == 'ip':
                    device["ip"] = "unknown"
                else:
                    raise KeyError(f"Missing required key '{key}' in the device dictionary. Provided data: {device}")


        netmiko_device = {
            'device_type': device_type,
            'ip': device['ip'],
            'username': device['username'],
            'password': device['password'],
            'global_delay_factor': 5,
        }
        if 'cisco' in platform.lower():
            netmiko_device['device_type'] = "cisco_xe"
        if not self.is_port_open(device['ip'], 22):
            logger.error(f"Port 22 is not open on {device['ip']}. Skipping device.")
            return []  # Early return to skip processing this device

        neighbors = []
        try:
            with ConnectHandler(**netmiko_device) as ssh:
                output = ssh.send_command(cli_command, expect_string=r"#")
                with open(f"{device['output_dir']}/{device['device_id']}_cli.txt", "w") as fh:
                    fh.write(output)
                parser = ttp(data=output, template=ttp_template)
                parser.parse()
                try:
                    result = parser.result()[0][0]
                    print(result)
                except Exception as e:
                    print(e)
                with open(f"{device['output_dir']}/{device['device_id']}_parsed.json", "w") as fhr:
                    fhr.write(json.dumps(result))

                current_unique_id = self.strip_domain(device['device_id'], device['domain_name'])
                unique_neighbors = {}
                print(f"domain name to strip: {device['domain_name']}")
                for neighbor in result:
                    if neighbor.get('platform', 'unknown') != 'unknown':
                        neighbor_id = self.strip_domain(neighbor.get('device_id', 'Unknown'), device['domain_name'])
                        local_port = neighbor.get('local_port', 'Unknown')
                        remote_port = neighbor.get('remote_port', 'Unknown')
                        device_id = neighbor.get('device_id', 'Unknown')

                        # Skip if any critical field is 'unknown'
                        if 'unknown' in [device_id, neighbor_id]:
                            continue

                        # Set unique_id to device_id
                        unique_id = device_id
                        neighbor['unique_id'] = unique_id

                        connection_key = (local_port, remote_port)

                        if unique_id != current_unique_id and not self.is_excluded(neighbor_id):
                            if unique_id not in unique_neighbors:
                                unique_neighbors[unique_id] = {
                                    **neighbor,
                                    'unique_id': unique_id,
                                    'username': device['username'],
                                    'password': device['password'],
                                    'vendor': device['vendor'],
                                    'protocol': device['protocol'],
                                    'domain_name': device['domain_name'],
                                    'output_dir': device['output_dir'],
                                    'connections': set()
                                }
                            unique_neighbors[unique_id]['connections'].add(connection_key)

                # Convert connections from set to list for consistency
                for neighbor in unique_neighbors.values():
                    neighbor['connections'] = list(neighbor['connections'])

                neighbors = [neighbor for neighbor in unique_neighbors.values() if 'unknown' not in neighbor.values()]

                logger.info(f"Fetched neighbors after filtering: {neighbors}")
        except Exception as e:
            logger.exception(f"Error fetching neighbors for {device['ip']}: {e}")
            self.failed_neighbors.append(device)

        # Save neighbors to a separate file for each iteration
        with open(f"{device['output_dir']}/neighbors_{device['device_id']}.json", "w") as fh:
            fh.write(json.dumps(neighbors, indent=2))

        return neighbors

    def strip_domain(self, device_id, domain):
        """Remove the domain name from the device identifier."""
        return device_id.split(domain)[0]

    def start_discovery(self):
        """Start the neighbor discovery process and construct the network map."""
        network_map = {}

        while not self.queue.empty():
            current_device = self.queue.get()
            device_id = self.strip_domain(current_device['device_id'], current_device['domain_name'])
            current_device['device_id'] = device_id
            current_device['unique_id'] = device_id

            if current_device['unique_id'] not in self.visited:
                self.visited.add(current_device['unique_id'])
                print(f"Node: {current_device}")
                neighbors = self.fetch_neighbors(current_device)

                if device_id not in network_map:
                    network_map[device_id] = {}

                for neighbor in neighbors:
                    neighbor_id = self.strip_domain(neighbor.get('unique_id', 'Unknown'),current_device['domain_name'])
                    if neighbor_id == 'Unknown':
                        logger.warning(
                            f"Skipping neighbor without a unique ID on port {neighbor.get('local_port', 'Unknown Port')}.")
                        continue

                    if neighbor_id not in network_map[device_id]:
                        network_map[device_id][neighbor_id] = {
                            'ip': neighbor.get('ip', 'Unknown'),
                            'platform': neighbor.get('platform', 'Unknown Platform'),
                            'connections': neighbor['connections']
                        }
                    else:
                        for connection in neighbor['connections']:
                            if connection not in network_map[device_id][neighbor_id]['connections']:
                                network_map[device_id][neighbor_id]['connections'].append(connection)

                    # Add to the queue if not already visited and not excluded
                    if neighbor_id not in self.visited and not self.is_excluded(neighbor['device_id']):
                        print(f"Adding neighbor: {neighbor_id}")
                        self.queue.put(neighbor)

                    # Debug output to track crawling
                    logger.debug(f"Queued {neighbor_id} for discovery.")

        return network_map

    def visited_devices(self):
        """Return the set of devices visited during discovery."""
        return self.visited

    def failed_devices(self):
        """Return the list of devices that couldn't be discovered."""
        return self.failed_neighbors
