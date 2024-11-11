import json
import logging
import re
from datetime import datetime
from queue import Queue
from typing import Set, List, Tuple, Optional, Dict

from func_timeout import func_timeout, FunctionTimedOut

from PySSHPass.pysshpass import SSHClientWrapper
from ttpfire import SimplifiedTTPEngine
from utils import DeviceData, NetworkCredentials


class NetworkDataGatherer:
    def __init__(self, template_dir: str = './templates', mib_dir: str = './mibs', max_workers: int = 5):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_discovery.log'),
                logging.StreamHandler()
            ]
        )

        self.logger = logging.getLogger(__name__)
        self.template_engine = SimplifiedTTPEngine(template_dir)
        self.queue = Queue()
        self.visited: Set[str] = set()
        self.failed_devices: List[Tuple[str, str]] = []
        self.vendor_handlers = {
            'ios': self._handle_cisco_connection,
            'nxos': self._handle_cisco_connection,
            'arista': self._handle_arista_connection,
            'aruba': self._handle_aruba_connection,
            # Add other OS handlers if applicable
            # 'paloalto': self._handle_paloalto_connection
        }
        self.command_groups = {
            'ios': {
                'version': ['show version'],
                'arp': ['show ip arp'],
                'cdp-detail': ['show cdp neighbors detail'],
                'lldp-detail': ['show lldp neighbors detail'],
                'int-status': ['show interfaces status'],
                'inventory': ['show inventory'],
                'mac': ['show mac address-table']
            },
            'nxos': {
                'version': ['show version'],
                'arp': ['show ip arp'],
                'cdp-detail': ['show cdp neighbors detail'],
                'lldp-detail': ['show lldp neighbors detail'],
                'int-status': ['show interface status'],
                'inventory': ['show inventory'],
                'mac': ['show mac address-table']
            },
            'arista': {
                'version': ['show version'],
                'arp': ['show ip arp'],
                'lldp-detail': ['show lldp neighbors detail'],
                'int-status': ['show interfaces status'],
                'inventory': ['show inventory'],
                'mac': ['show mac address-table']
            },
            'aruba': {
                'version': ['show version'],
                'arp': ['show arp'],
                'lldp-detail': ['show lldp neighbors detail'],
                'int-status': ['show interfaces brief'],
                'inventory': ['show system'],
                'mac': ['show mac-address-table']
            },
            'paloalto': {
                'version': ['show system info'],
                'arp': ['show arp all'],
                'int-status': ['show interface all'],
                'inventory': ['show system info']
            }
        }


    def _detect_os_type(self, sys_descr: str) -> str:
        """Identify the device OS type based on sysDescr."""
        sys_descr = sys_descr.lower()
        if 'nx-os' in sys_descr or 'nexus' in sys_descr:
            return 'nxos'
        elif 'ios-xe' in sys_descr or 'cisco' in sys_descr:
            return 'ios'
        elif 'ios' in sys_descr or 'cisco' in sys_descr:
            return 'ios'
        elif 'eos' in sys_descr or 'arista' in sys_descr:
            return 'arista'
        elif 'arubaos' in sys_descr or 'procurve' in sys_descr:
            return 'aruba'
        elif 'panos' in sys_descr or 'pan-os' in sys_descr:
            return 'paloalto'
        return 'unknown'  # Default to unknown if OS cannot be identified

    def crawl_network(self, seed_ip: str, credentials: NetworkCredentials, domain_name: str = '') -> Dict[
        str, DeviceData]:
        """
        Perform a single-threaded Breadth-First Search (BFS) network discovery, gathering SNMP and CLI data.
        """
        # Clear tracking structures for a new discovery session
        self.visited.clear()
        self.queue.queue.clear()
        self.failed_devices.clear()

        # Initialize a collection to store discovered devices
        device_collection = {}

        # Initialize the queue with the seed device
        self.queue.put({
            'ip': seed_ip,
            'credentials': credentials,
            'domain_name': domain_name
        })

        while not self.queue.empty():
            # Retrieve the next device in the queue
            device = self.queue.get_nowait()

            # Create DeviceData instance for the current device
            device_data = DeviceData(ip_address=device['ip'])

            # Get unique ID by passing the DeviceData object (only once)
            unique_id = self.get_unique_device_id(device_data, domain_name, credentials)

            # Only process new devices that have a valid unique ID and have not been visited
            if unique_id and unique_id not in self.visited:
                print(f"Unique id result: {unique_id}")

                # Attempt to gather CLI data if SNMP collection succeeded
                self.gather_device_data(device['ip'], credentials, device_data)

                # Process the device after gathering data
                self._process_device(device, device_data, unique_id)

                # Add device to visited after fully processing it
                self.visited.add(unique_id)

                # Add to collection after processing
                device_collection[unique_id] = device_data
                print(f"Device Collection: {device_collection}")

        return device_collection

    def gather_device_data(self, ip: str, credentials: NetworkCredentials, device_data: DeviceData) -> None:
        """
        Collect SNMP and CLI data from the device to maximize information retrieval.
        """
        self.logger.debug(f"Starting data gathering for device at IP: {ip}")

        # Attempt SNMP collection
        snmp_data = self._try_snmp_collection(ip, credentials.snmp_communities)
        print(f"snmp data: {snmp_data}")
        if snmp_data:
            try:
                device_data.collected_data['snmp'] = snmp_data
                device_data.access_info['snmp_works'] = True
                device_data.access_info['working_community'] = snmp_data['working_community']
                print(f"Device data: {device_data}")
                # Detect OS type
                sys_descr = snmp_data.get('system', {}).get('sysDescr', '')
                os_type = self._detect_os_type(sys_descr)
                device_data.access_info['os_type'] = os_type
                self.logger.debug(f"Detected OS type for {ip}: {os_type}")
            except Exception as e:
                print(e)
        # Always attempt CLI collection if OS type is recognized
        os_type = device_data.access_info.get('os_type', 'unknown')
        if os_type in self.vendor_handlers:
            self.logger.debug(f"Attempting CLI collection for {ip} with detected OS type: {os_type}")
            ssh_data, prompt = self._try_ssh_collection(ip, credentials, os_type)
            if ssh_data:
                device_data.collected_data['cli'] = ssh_data
                device_data.access_info['ssh_works'] = True
                device_data.access_info['prompt'] = prompt
                self.logger.debug(f"CLI data collected for {ip}: {ssh_data}")
            else:
                self.logger.warning(f"CLI data collection failed for device at IP {ip}")
        else:
            self.logger.warning(f"Unrecognized OS type '{os_type}' for device {ip}. Skipping CLI data collection.")

    def _try_ssh_collection(self, ip: str, credentials: NetworkCredentials, os_type: str) -> Tuple[
        Optional[Dict], Optional[str]]:
        """
        Execute CLI commands using OS-specific vendor handlers.
        """
        self.logger.debug(f"Attempting SSH collection for {ip} with OS type {os_type}")
        try:
            handler = self.vendor_handlers.get(os_type)

            if handler:
                self.logger.info(f"Invoking handler for OS type '{os_type}' on device {ip}")

                ssh_data, prompt = handler(ip, credentials)
                self.logger.debug(f"SSH data collected from handler: {ssh_data}, prompt: {prompt}")
                return ssh_data, prompt
            else:
                self.logger.warning(
                    f"No SSH handler defined for OS type '{os_type}' on device {ip}. Skipping CLI collection.")
                return None, None
        except Exception as e:
            self.logger.error(f"SSH collection failed for device {ip} with OS type '{os_type}': {str(e)}")
            return None, None

    def _try_cli_parse(self, output: str, group: str) -> Optional[Dict]:
        try:
            output = re.sub(r'[\x1B\x9B][\[\]()#;?]*(?:(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nq-uy=><~])', '', output)

            group_template_engine = SimplifiedTTPEngine(f"./templates/{group}")
            template, parsed_data, score = group_template_engine.find_best_template(output)
            if score > 1:
                self.logger.info(f"Successfully parsed {group} data using template {template} with score {score}")
                return parsed_data
            else:
                self.logger.debug(f"No good match for {group}. Best score: {score}")
                return None
        except Exception as e:
            self.logger.debug(f"Error parsing {group} output: {str(e)}")
            return None

    def _handle_cisco_connection(self, ip: str, credentials: NetworkCredentials) -> Tuple[
        Optional[Dict], Optional[str]]:
        """
        Handle SSH connection and execute Cisco-specific commands.
        """
        try:
            print(f"Starting Cisco SSH connection for {ip}")

            ssh_client = SSHClientWrapper(
                host=ip,
                user=credentials.ssh_username,
                password=credentials.ssh_password,
                invoke_shell=True,
                prompt="#",
                prompt_count=3,
                timeout=30,
                quiet=True,
                delay=0.5
            )
            ssh_client.connect()
            prompt = ssh_client.find_prompt(ends_with="#")
            print(f"Initial prompt found for {ip}: {prompt}")

            # Enter enable mode if needed
            if credentials.enable_password and '>' in prompt:
                ssh_client.cmds = f"enable\n{credentials.enable_password}"
                ssh_client.run_commands()
                prompt = ssh_client.find_prompt("#")
                self.logger.debug(f"Prompt after enable mode for {ip}: {prompt}")

            # Disable paging
            ssh_client.cmds = "terminal length 0,,"
            ssh_client.run_commands()
            print(f"Paging disabled for device {ip}")

            collected_data = {}
            commands = self.command_groups.get('ios', {})  # Use IOS commands as default for Cisco devices

            for group, group_commands in commands.items():
                for command in group_commands:
                    try:
                        self.logger.debug(f"Running command on {ip}: {command}")
                        ssh_client.cmds = f"{command},,"
                        output = ssh_client.run_commands()
                        if output:
                            parsed_data = self._try_cli_parse(output, group)
                            self.logger.debug(f"Parsed data for command '{command}' on {ip}: {parsed_data}")
                            if parsed_data:
                                collected_data[group] = parsed_data
                                break
                    except Exception as e:
                        self.logger.debug(f"Command '{command}' failed on {ip}: {str(e)}")
                        continue

            ssh_client.close()
            return collected_data, prompt

        except Exception as e:
            self.logger.error(f"SSH collection failed for Cisco device at {ip}: {str(e)}")
            return None, None

    def _process_device(self, device: Dict, device_data: DeviceData, unique_id: str) -> None:
        """
        Process the device, specifically gathering neighbors via CLI if available.
        """
        try:
            # Process neighbors if CLI data is available
            if 'cli' in device_data.collected_data:
                self._process_neighbors(device_data, device['credentials'], device['domain_name'])
            else:
                self.logger.warning(f"No CLI data available for device {unique_id}. Skipping neighbor processing.")
        except Exception as e:
            error_msg = f"Error processing device {device['ip']}: {str(e)}"
            self.logger.error(error_msg)
            self.failed_devices.append((device['ip'], error_msg))

    from typing import Dict, Optional

    # Inside your NetworkDataGatherer class
    def _try_snmp_collection(self, ip: str, communities: List[str]) -> Optional[Dict]:
        """
        Attempt SNMP collection, falling back to SSH if SNMP fails entirely.
        """

        return self._last_effort_ssh_collection(ip)

    def _last_effort_ssh_collection(self, ip: str) -> Optional[Dict]:
        """
        Fallback method to use SSH to retrieve sysName and sysDescr if SNMP collection fails,
        with a timeout of 60 seconds.
        """
        try:
            # Run the main collection logic with a 30-second timeout
            return func_timeout(30, self._actual_last_effort_ssh_collection, args=(ip,))
        except FunctionTimedOut:
            print(f"SSH fallback collection for {ip} timed out after 60 seconds.")
            return None

    def _actual_last_effort_ssh_collection(self, ip: str) -> Optional[Dict]:
        """
        Actual SSH fallback logic, separated to allow func_timeout to manage timeouts.
        """
        try:
            print(f"Attempting SSH fallback collection for {ip}")
            ssh_client = SSHClientWrapper(
                host=ip,
                user="cisco",
                password="cisco",
                invoke_shell=True,
                prompt="#",
                prompt_count=3,
                timeout=15,  # Individual SSH timeout
                quiet=True,
                delay=0.5
            )

            # Connect and find the prompt as sysName
            ssh_client.connect()
            prompt = ssh_client.find_prompt(ends_with="#")
            sys_name = prompt.split('#')[0].strip()

            # Run `show version` to get vendor information
            ssh_client.cmds = "term len 0, show version,,"
            output = ssh_client.run_commands()

            # Parse the vendor name from `show version` output
            sys_descr = None
            parsed_data = self._try_cli_parse(output, "version")

            # Flatten parsed data if it's a nested list
            if parsed_data and isinstance(parsed_data[0], list):
                parsed_data = parsed_data[0]

            # Format sys_descr
            if parsed_data:
                vendor = parsed_data[0].get("vendor", "")
                model = parsed_data[0].get("model", "Unknown Model")
                os_version = parsed_data[0].get("os_version", "Unknown OS Version")
                sys_descr = f"{vendor} {model} running software version {os_version}"
            else:
                sys_descr = "Unknown sysDescr"

            ssh_client.close()

            # Return the collected data in the expected format
            return {
                'system': {'sysName': sys_name, 'sysDescr': sys_descr or "unknown vendor"},
                'interfaces': {},
                'working_community': "SSH fallback"
            }

        except Exception as e:
            print(f"SSH fallback collection failed for {ip}: {str(e)}")
            return None


    def _process_neighbors(self, device_data: DeviceData, credentials: NetworkCredentials, domain_name: str) -> None:
        """
        Queue neighbors for BFS traversal based on hostname-based identification.
        """
        self.logger.debug(f"Processing neighbors for device {device_data.ip_address}")

        # Process neighbors from CLI 'cdp-detail' or 'lldp-detail'
        neighbors = device_data.collected_data.get('cli', {}).get('cdp-detail', []) + \
                    device_data.collected_data.get('cli', {}).get('lldp-detail', [])

        for neighbor in neighbors:
            neighbor_id = self.strip_domain(neighbor.get('device_id', ''), domain_name)
            neighbor_ip = neighbor.get('ip_address')
            self.logger.debug(f"Found neighbor: {neighbor_id} with IP {neighbor_ip}")

            # Queue the neighbor without marking it as visited yet
            if neighbor_id and neighbor_ip:
                self.logger.info(f"Queuing neighbor {neighbor_id} with IP {neighbor_ip} for BFS processing.")
                self.queue.put({
                    'ip': neighbor_ip,
                    'credentials': credentials,
                    'domain_name': domain_name
                })
            else:
                self.logger.debug(f"Neighbor {neighbor_id} has missing IP or device ID, skipping.")

    def get_unique_device_id(self, device_data: DeviceData, domain_name: str, credentials: NetworkCredentials) -> \
    Optional[str]:
        """
        Determine a unique device identifier using SNMP sysName primarily.
        Retry SNMP if sysName is missing. Return None if device is already visited.
        """
        self.logger.debug(f"Attempting to determine unique ID for {device_data.ip_address}")
        unique_id = None  # Default to None if identification fails

        # Check if sysName is available from prior SNMP collection

        sys_name = device_data.collected_data.get('snmp', {}).get('system', {}).get('sysName')

        if sys_name is None:
            snmp_data = self._try_snmp_collection(device_data.ip_address, credentials.snmp_communities)
            try:
                sys_name = snmp_data['system']['sysName']
            except:
                return None


        if not sys_name:
            self.logger.debug(
                f"No sysName found in initial SNMP data for {device_data.ip_address}. Retrying SNMP collection.")
            snmp_data = self._try_snmp_collection(device_data.ip_address, credentials.snmp_communities)
            if snmp_data:
                self.logger.debug(
                    f"SNMP data successfully retrieved on retry for {device_data.ip_address}: {snmp_data}")
                device_data.collected_data['snmp'] = snmp_data
                device_data.access_info['snmp_works'] = True
                device_data.access_info['working_community'] = snmp_data['working_community']
                sys_name = snmp_data.get('system', {}).get('sysName')
                sys_descr = snmp_data.get('system', {}).get('sysDescr', '')
                device_data.access_info['os_type'] = self._detect_os_type(sys_descr)

        # Use SNMP sysName if available after retry
        if sys_name:
            unique_id = self.strip_domain(sys_name, domain_name)
            if unique_id in self.visited:
                print("Visited")
                print(self.visited)
                self.logger.debug(f"Device {unique_id} already visited, skipping.")
                return None  # Device has already been visited

        # Fallback to SSH prompt as unique ID if SNMP sysName is unavailable
        if unique_id is None:
            prompt = device_data.access_info.get('prompt')
            if not prompt:
                os_type = device_data.access_info.get('os_type', 'unknown')
                _, prompt = self._try_ssh_collection(device_data.ip_address, credentials, os_type)
                if prompt:
                    device_data.access_info['prompt'] = prompt

            if prompt:
                unique_id = prompt.split('#')[0].strip()
                if unique_id in self.visited:
                    self.logger.debug(f"Device {unique_id} already visited, skipping.")
                    return None  # Device has already been visited

        # Log an error if no unique ID is found
        if unique_id is None:
            self.logger.error(
                f"Unable to assign unique ID: No sysName or CLI prompt found for {device_data.ip_address}")

        return unique_id

    def strip_domain(self, device_id: str, domain: str) -> str:
        """Remove domain name from device identifier, considering multiple subdomains."""
        if not device_id or not domain:
            return device_id

        # Split domain and device_id into segments
        domain_parts = domain.split('.')
        device_parts = device_id.split('.')

        # Find the start index where domain parts match the device parts from the end
        match_index = next(
            (i for i in range(len(device_parts) - len(domain_parts), len(device_parts))
             if device_parts[i:] == domain_parts), None
        )

        # If a match was found, keep only the hostname part
        if match_index is not None:
            return '.'.join(device_parts[:match_index])
        return device_id



    def _handle_arista_connection(self, ip: str, credentials: NetworkCredentials) -> Tuple[
        Optional[Dict], Optional[str]]:
        try:
            username = credentials.arista_credentials.get('username') or credentials.ssh_username
            password = credentials.arista_credentials.get('password') or credentials.ssh_password

            ssh_client = SSHClientWrapper(
                host=ip,
                user=username,
                password=password,
                invoke_shell=True,
                prompt="#",
                prompt_count=3,
                timeout=30,
                quiet=True,
                delay=0.5
            )

            ssh_client.connect()
            prompt = ssh_client.find_prompt("#")

            # Disable paging
            ssh_client.cmds = "terminal length 0,,"
            ssh_client.run_commands()

            collected_data = {}
            commands = self.command_groups['arista']

            for group, group_commands in commands.items():
                for command in group_commands:
                    try:
                        ssh_client.cmds = f"{command},,"
                        output = ssh_client.run_commands()
                        if output:
                            parsed_data = self._try_cli_parse(output, group)
                            if parsed_data:
                                collected_data[group] = parsed_data
                                break
                    except Exception as e:
                        self.logger.debug(f"Command '{command}' failed on {ip}: {str(e)}")
                        continue

            ssh_client.close()
            return collected_data, prompt

        except Exception as e:
            self.logger.error(f"Arista connection failed for {ip}: {str(e)}")
            return None, None

    def _handle_aruba_connection(self, ip: str, credentials: NetworkCredentials) -> Tuple[
        Optional[Dict], Optional[str]]:
        try:
            username = credentials.aruba_credentials.get('username') or credentials.ssh_username
            password = credentials.aruba_credentials.get('password') or credentials.ssh_password

            ssh_client = SSHClientWrapper(
                host=ip,
                user=username,
                password=password,
                invoke_shell=True,
                prompt="#",
                prompt_count=3,
                timeout=30,
                quiet=True,
                delay=0.5
            )

            ssh_client.connect()
            prompt = ssh_client.find_prompt("#")

            # Disable paging
            ssh_client.cmds = "no paging,,"
            ssh_client.run_commands()

            collected_data = {}
            commands = self.command_groups['aruba']

            for group, group_commands in commands.items():
                for command in group_commands:
                    try:
                        ssh_client.cmds = f"{command},,"
                        output = ssh_client.run_commands()
                        if output:
                            parsed_data = self._try_cli_parse(output, group)
                            if parsed_data:
                                collected_data[group] = parsed_data
                                break
                    except Exception as e:
                        self.logger.debug(f"Command '{command}' failed on {ip}: {str(e)}")
                        continue

            ssh_client.close()
            return collected_data, prompt

        except Exception as e:
            self.logger.error(f"Aruba connection failed for {ip}: {str(e)}")
            return None, None

    def _get_snmp_value(self, ip: str, community: str, oid: str) -> Optional[str]:
        """Retrieve a single SNMP value from the device."""

        return None

    def _get_interface_mapping(self, ip: str, community: str) -> Dict[str, str]:
        """Retrieve interface mapping from SNMP for the given device."""
        interface_map = {}

        return interface_map

    def export_data(self, data: Dict[str, DeviceData], filename: str):
        """Export collected data to JSON with enhanced summary"""
        output = {
            'timestamp': datetime.now().isoformat(),
            'devices': {},
            'summary': {
                'total_devices': len(data),
                'snmp_accessible': len([d for d in data.values() if d.access_info['snmp_works']]),
                'ssh_accessible': len([d for d in data.values() if d.access_info['ssh_works']]),
                'os_types': {},
                'failed_devices': self.failed_devices,
                'discovery_duration': str(max(d.discovery_time for d in data.values()) -
                                          min(d.discovery_time for d in data.values())) if data else "0"
            }
        }

        # Count OS types
        for device in data.values():
            os_type = device.access_info.get('os_type', 'unknown')
            output['summary']['os_types'][os_type] = output['summary']['os_types'].get(os_type, 0) + 1

        # Export device data
        for device_id, device in data.items():
            output['devices'][device_id] = {
                'ip_address': device.ip_address,
                'access_info': device.access_info,
                'collected_data': device.collected_data,
                'collection_errors': device.collection_errors,
                'discovery_time': device.discovery_time.isoformat()
            }

        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)

        # Export CSV summary
        self._export_csv_summary(data, filename.replace('.json', '_summary.csv'))

    def _export_csv_summary(self, data: Dict[str, DeviceData], filename: str):
        """Export a CSV summary of discovered devices."""
        with open(filename, 'w') as f:
            f.write('Device ID,IP Address,SSH Status,SNMP Status,OS Type,Error Count,Discovery Time\n')
            for device_id, device in data.items():
                f.write(f'{device_id},{device.ip_address},{device.access_info["ssh_works"]},')
                f.write(f'{device.access_info["snmp_works"]},{device.access_info.get("os_type", "unknown")},')
                f.write(f'{len(device.collection_errors)},{device.discovery_time.isoformat()}\n')
