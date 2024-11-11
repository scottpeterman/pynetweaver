import json
import socket
from queue import Queue
from netmiko import ConnectHandler
from ttp import ttp
import logging
from tabulate import tabulate
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CDPHandler:
    def __init__(self, vendor, exclude_string):
        self.vendor = vendor
        self.exclude = [s.strip() for s in exclude_string.split(',')]
        self.queue = Queue()
        self.visited = set()
        self.failed_neighbors = []
        self.network_map = {}
        self.ttp_templates = [
            '''
Device ID: {{ device_id }}
  IP address: {{ ip | default("undefined") }}
Platform: {{ platform | ORPHRASE | default("unknown") }},  Capabilities: {{ capabilities | ORPHRASE | default("unknown")}}
Interface: {{ local_port | ORPHRASE }},  Port ID (outgoing port): {{ remote_port | ORPHRASE }}
''',
            '''
System Name: {{ device_id }}
Interface address(es): {{ ip_count }}
    IPv4 Address: {{ ip }}
Platform: {{ platform | ORPHRASE }}, Capabilities:  {{ capabilities | ORPHRASE }}
Interface: {{ local_port | ORPHRASE }},  Port ID (outgoing port): {{ remote_port | ORPHRASE }}
''',
        ]

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

    def sanitize_output(self, neighbors):
        sanitized = []
        for neighbor in neighbors:
            sanitized_neighbor = neighbor.copy()
            if 'password' in sanitized_neighbor:
                sanitized_neighbor['password'] = '*****'  # Masking the password
            sanitized.append(sanitized_neighbor)
        return sanitized

    def format_output(self, neighbors):
        sanitized_neighbors = self.sanitize_output(neighbors)
        headers = [ "Device ID", "Platform", "IP"]
        table = []
        for neighbor in sanitized_neighbors:
            row = [
                neighbor.get('device_id', ''),
                neighbor.get('platform', ''),
                neighbor.get('ip', ''),
            ]
            table.append(row)
        return tabulate(table, headers=headers, tablefmt="grid")
    def fetch_neighbors(self, device):
        """Fetch neighbors using CDP data while applying exclusion rules."""
        required_keys = ['ip', 'username', 'password']
        retries = 3
        neighbors = []

        # Check for required keys in the device dictionary
        for key in required_keys:
            if key not in device:
                raise KeyError(f"Missing required key '{key}' in the device dictionary. Provided device data: {device}")

        # Check if SSH port is open before proceeding
        if not self.is_port_open(device['ip'], 22):
            logger.info(f"Port 22 is not open on {device['ip']}. Skipping SSH connection.")
            return neighbors

        # Prepare the Netmiko device connection configuration
        netmiko_device = {
            'device_type': 'cisco_ios',
            'ip': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }

        try:
            with ConnectHandler(**netmiko_device) as ssh:
                for attempt in range(retries):
                    try:
                        output = ssh.send_command('show cdp neighbors detail')
                        break
                    except Exception as e:
                        logger.error(f"Error fetching neighbors (Attempt {attempt + 1}/{retries}): {str(e)}")
                        if attempt == retries - 1:
                            raise

                with open(f"{device['output_dir']}/{device['device_id']}_cli.txt", "w") as fh:
                    fh.write(output)

                best_result = []
                max_keys = 0

                # Determine the best template to parse with
                for template in self.ttp_templates:
                    parser = ttp(data=output, template=template)
                    parser.parse()
                    result = parser.result()

                    if isinstance(result[0][0], list):
                        parsed_neighbors = result[0][0]
                    elif isinstance(result[0][0], dict):
                        parsed_neighbors = [result[0][0]]
                    else:
                        parsed_neighbors = []

                    num_keys = len(parsed_neighbors[0].keys()) if parsed_neighbors else 0

                    if num_keys > max_keys:
                        max_keys = num_keys
                        best_result = parsed_neighbors

                current_unique_id = self.strip_domain(device['device_id'], device['domain_name'])
                unique_neighbors = {}

                # Track neighbors with unique connections
                for neighbor in best_result:
                    neighbor_id = self.strip_domain(neighbor.get('device_id', 'Unknown'), device['domain_name'])
                    local_port = neighbor.get('local_port', 'Unknown')
                    remote_port = neighbor.get('remote_port', 'Unknown')

                    if neighbor_id != current_unique_id and not self.is_excluded(neighbor_id):
                        if neighbor_id not in unique_neighbors:
                            unique_neighbors[neighbor_id] = {
                                **neighbor,
                                'unique_id': neighbor_id,
                                'username': device['username'],
                                'password': device['password'],
                                'vendor': device['vendor'],
                                'protocol': device['protocol'],
                                'domain_name': device['domain_name'],
                                'output_dir': device['output_dir'],
                                'connections': set()
                            }

                        unique_neighbors[neighbor_id]['connections'].add((local_port, remote_port))

                # Convert connections to list
                for neighbor in unique_neighbors.values():
                    neighbor['connections'] = list(neighbor['connections'])

                neighbors = [neighbor for neighbor in unique_neighbors.values()]

                logger.info(f"Fetched neighbors after filtering: {neighbors}")

        except Exception as e:
            logger.exception(f"Error fetching neighbors for {device['ip']}: {str(e)}")
            self.failed_neighbors.append(device)
        with open("debug_map.json", "w") as fhd:
            fhd.write(json.dumps(neighbors, indent=2))
            print("---------------------------------------- dump")
            formatted_output = self.format_output(neighbors)
            print(formatted_output)
            print("--------------- end dump")
        return neighbors

    def strip_domain(self, device_id, domain):
        """Remove the domain name from the device identifier."""
        return device_id.split(domain)[0] if domain in device_id else device_id

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
                neighbors = self.fetch_neighbors(current_device)

                if device_id not in network_map:
                    network_map[device_id] = {}

                for neighbor in neighbors:
                    neighbor_id = neighbor.get('unique_id', 'Unknown')
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
                        self.queue.put(neighbor)

        return network_map

    def visited_devices(self):
        """Return the set of devices visited during discovery."""
        return self.visited

    def failed_devices(self):
        """Return the list of devices that couldn't be discovered."""
        return self.failed_neighbors