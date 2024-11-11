import json
from typing import Dict, Any, List


import json
from typing import Dict, Any, List


def process_neighbor_data(neighbors: List[Dict], protocol: str) -> List[Dict]:
    """
    Normalize CDP and LLDP neighbor data into a common format.
    Strips FQDN from device_id if present.
    """
    processed = []
    for neighbor in neighbors:
        # Skip neighbors with no device ID or "unknown" in ID
        device_id = neighbor.get("device_id")
        if not device_id or "unknown" in device_id.lower():
            continue

        # Strip FQDN from device_id (e.g., "switch.example.com" -> "switch")
        device_id = device_id.split(".")[0]

        # Get interface information - handle both CDP and LLDP formats
        local_interface = neighbor.get("local_interface")
        remote_interface = neighbor.get("remote_interface", "")

        # Clean up remote interface (remove quotes if present)
        if isinstance(remote_interface, str):
            remote_interface = remote_interface.strip('"')

        # Skip if we don't have both interfaces
        if not local_interface or not remote_interface:
            continue

        processed.append({
            "device_id": device_id,
            "ip": neighbor.get("ip_address", "Unknown"),
            "platform": neighbor.get("platform", "Unknown Platform"),
            "local_interface": local_interface,
            "remote_interface": remote_interface,
            "capabilities": neighbor.get("capabilities", "")
        })

    return processed


def convert_ds2_to_topology(ds2_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert ds2.py JSON output format to topology mapping format.
    Handles both CDP and LLDP neighbor data.
    """
    topology = {}

    # Process each device in the ds2 data
    for device_id, device_data in ds2_data.get("devices", {}).items():
        # Initialize node entry
        if device_id not in topology:
            topology[device_id] = {
                "node_details": {
                    "ip": device_data.get("ip_address", "Unknown"),
                    "platform": device_data.get("access_info", {}).get("os_type", "Unknown Platform")
                },
                "peers": {}
            }

        # Get CLI data containing neighbor information
        cli_data = device_data.get("collected_data", {}).get("cli", {})

        # Process both CDP and LLDP neighbors
        all_neighbors = []

        # Add CDP neighbors if present
        if "cdp-detail" in cli_data:
            cdp_neighbors = process_neighbor_data(cli_data["cdp-detail"], "cdp")
            all_neighbors.extend(cdp_neighbors)

        # Add LLDP neighbors if present
        if "lldp-detail" in cli_data:
            lldp_neighbors = process_neighbor_data(cli_data["lldp-detail"], "lldp")
            all_neighbors.extend(lldp_neighbors)

        # Process all neighbors
        for neighbor in all_neighbors:
            neighbor_id = neighbor["device_id"]

            # Initialize or update peer entry
            if neighbor_id not in topology[device_id]["peers"]:
                topology[device_id]["peers"][neighbor_id] = {
                    "ip": neighbor["ip"],
                    "platform": neighbor["platform"],
                    "connections": []
                }

            # Add connection if it's not already present
            connection = [neighbor["local_interface"], neighbor["remote_interface"]]
            if connection not in topology[device_id]["peers"][neighbor_id]["connections"]:
                topology[device_id]["peers"][neighbor_id]["connections"].append(connection)

    return topology


def main():
    # Example usage
    with open("usa.json", "r") as f:
        ds2_data = json.load(f)

    topology = convert_ds2_to_topology(ds2_data)

    # Save the converted topology
    with open("topology_map.json", "w") as f:
        json.dump(topology, f, indent=2)

    print(f"Processed {len(topology)} nodes into topology format")
    print("Note: Map includes data from both CDP and LLDP where available")


if __name__ == "__main__":
    main()