import json
from netmiko import ConnectHandler
from map_generator.cdp_handler import CDPHandler
from map_generator.lldp_handler import LLDPHandler
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DiscoveryCoordinator:
    def __init__(self, seed_device, exclude_string='', map_name='Network_map.graphml', drawio_name='Network_diagram.drawio', layout_algo='rt'):
        """
        Initializes the DiscoveryCoordinator with seed device information and exclusion rules.

        :param seed_device: Dictionary containing initial device information (IP, vendor, protocol, etc.).
        :param exclude_string: Comma-separated string of device types to exclude from discovery.
        :param map_name: Name of the output graphml map file.
        :param drawio_name: Name of the output drawio map file.
        :param layout_algo: Graph layout algorithm to use.
        """
        self.seed_device = seed_device
        self.exclude_string = exclude_string
        self.map_name = map_name
        self.drawio_name = drawio_name
        self.layout_algo = layout_algo
        self.visited = set()
        self.failed_devices = []

    def _map_protocol_vendor_to_device_type(self, protocol, vendor):
        """
        Maps protocol and vendor to a Netmiko device type string.

        :param protocol: Protocol used (cdp or lldp).
        :param vendor: Vendor name (cisco, arista, etc.).
        :return: Netmiko device type string or None if not supported.
        """
        protocol = protocol.lower()
        vendor = vendor.lower()

        # Adjust mappings based on protocol and vendor combinations
        if protocol == 'cdp':
            if vendor == 'cisco':
                return 'cisco_ios'
        elif protocol == 'lldp':
            if vendor == 'arista':
                return 'arista_eos'
            elif vendor == 'aruba':
                return 'hp_procurve'
        return None

    def _get_seed_device_id(self):
        """Fetches the device ID by connecting to the seed device and parsing the command prompt."""
        # Determine the device type (replace with accurate logic if necessary)
        device_type = self._map_protocol_vendor_to_device_type(self.seed_device['protocol'], self.seed_device['vendor'])
        if not device_type:
            logger.error(
                f"Unsupported combination of protocol '{self.seed_device['protocol']}' and vendor '{self.seed_device['vendor']}'")
            return None

        # Netmiko connection dictionary
        netmiko_device = {
            'device_type': device_type,
            'ip': self.seed_device['ip'],
            'username': self.seed_device['username'],
            'password': self.seed_device['password'],
            'timeout': 20
        }

        try:
            with ConnectHandler(**netmiko_device) as ssh:
                prompt = ssh.find_prompt()
                device_id = prompt.strip("#>").strip()
                return device_id

        except Exception as e:
            logger.exception(f"Error retrieving device ID for {self.seed_device['ip']}: {str(e)}")
            return None

    def _get_handler(self):
        """
        Returns the appropriate handler class based on the protocol.

        :return: CDPHandler or LLDPHandler instance
        """
        protocol = self.seed_device['protocol'].lower()
        vendor = self.seed_device['vendor'].lower()

        if protocol == 'cdp':
            return CDPHandler(vendor, self.exclude_string)
        elif protocol == 'lldp':
            return LLDPHandler(vendor, self.exclude_string)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    def discover(self):
        """
        Starts the neighbor discovery process using the appropriate handler
        and returns a structured map containing node details and peers.
        """
        # Retrieve the seed device's ID dynamically
        device_id = self._get_seed_device_id()
        if not device_id:
            raise ValueError("Could not retrieve seed device ID.")
        self.seed_device['device_id'] = device_id.split("#")[0]
        self.seed_device['node_details'] = {"ip": self.seed_device['ip'], "platform": self.seed_device['vendor']}

        try:
            # Initialize the handler with the seed device
            handler = self._get_handler()
            handler.set_seed_device(self.seed_device)

            # Execute the discovery process and retrieve the network map
            raw_map = handler.start_discovery()
            print(f"raw_map: {raw_map}")

            # Initialize a new structure to store details and peers together
            structured_map = {}

            for device_id, peers in raw_map.items():
                # Extract node details
                node_details = {
                    "ip": next((peer['ip'] for peer in peers.values() if 'ip' in peer), "Unknown"),
                    "platform": next((peer['platform'] for peer in peers.values() if 'platform' in peer), "Unknown Platform")
                }

                structured_map[device_id] = {
                    "node_details": node_details,
                    "peers": peers
                }

            # Track visited devices and failures
            self.visited = handler.visited_devices()
            self.failed_devices = handler.failed_devices()

        except Exception as e:
            logger.exception("An error occurred during the discovery process.")
            raise

        with open("structured_map.json", "w") as fhs:
            fhs.write(json.dumps(structured_map, indent=2))

        return structured_map

    def visited_devices(self):
        """
        Returns the set of visited devices during discovery.

        :return: Visited devices (set)
        """
        return self.visited

    def failed_devices(self):
        """
        Returns the list of devices that failed during discovery.

        :return: Failed devices (list)
        """
        return self.failed_devices
