import os
import json
from map_generator.discovery_coordinator import DiscoveryCoordinator
from map_generator.mapping_tools import create_network_diagrams


def run_discovery(
        seed_ip,
        device_ip,
        username,
        password,
        vendor,
        protocol,
        domain_name,
        exclude_string,
        map_name,
        output_dir,
        layout_algo
) -> dict:
    """
    Execute network discovery and generate network maps.
    """
    # Validate input to ensure all required parameters are provided
    required_params = {
        'seed_ip': seed_ip,
        'device_ip': device_ip,
        'username': username,
        'password': password,
        'vendor': vendor,
        'protocol': protocol,
        'domain_name': domain_name,
        'exclude_string': exclude_string,
        'map_name': map_name,
        'output_dir': output_dir,
        'layout_algo': layout_algo
    }
    missing_params = [param for param, value in required_params.items() if value is None]
    if missing_params:
        raise ValueError(f"Missing required parameters: {', '.join(missing_params)}")

    # Ensure output directory exists and is not root
    output_dir = os.path.abspath(output_dir)
    if output_dir == os.path.abspath('./'):
        raise ValueError("The output directory cannot be set to the root './'. Please specify a different directory.")

    if not os.path.exists(output_dir):
        print(f"Creating output directory: {output_dir}")
        os.makedirs(output_dir)
    else:
        print(f"Using existing output directory: {output_dir}")

    # Construct file paths within the output directory
    graphml_filename = os.path.join(output_dir, f"{map_name}.graphml")
    drawio_filename = os.path.join(output_dir, f"{map_name}.drawio")
    network_map_json_path = os.path.join(output_dir, f"{map_name}.json")

    # Debugging: Print file paths for verification
    print(f"Debug: GraphML file will be saved to: {graphml_filename}")
    print(f"Debug: DrawIO file will be saved to: {drawio_filename}")
    print(f"Debug: Network map JSON file will be saved to: {network_map_json_path}")

    # Seed device configuration with restored properties
    seed_device = {
        'ip': seed_ip or device_ip,
        'username': username,
        'password': password,
        'vendor': vendor,
        'protocol': protocol,
        'domain_name': domain_name,
        'output_dir': output_dir,  # Ensure output_dir matches expected structure
        'node_details': {
            "ip": seed_ip or device_ip,
            "platform": vendor
        }
    }

    # Initialize the discovery coordinator
    coordinator = DiscoveryCoordinator(
        seed_device,
        exclude_string,
        os.path.basename(graphml_filename),
        os.path.basename(drawio_filename),
        layout_algo
    )

    # Execute the discovery process and retrieve the network map
    network_map = coordinator.discover()

    # Define the base output directory and "map" subfolder
    map_folder = os.path.join(output_dir, "map")
    os.makedirs(map_folder, exist_ok=True)  # Creates output_dir + "./map" if it doesn't exist

    # Define the JSON path within the "map" subfolder
    network_map_json_path = os.path.join(map_folder, f"{map_name}.json")

    # Save the network map as a JSON file
    with open(network_map_json_path, 'w') as json_file:
        json.dump(network_map, json_file, indent=2)
        print(f"Debug: Network map JSON saved successfully at {network_map_json_path}")

    # Create network diagrams with paths relative to the output directory
    create_network_diagrams(
        json_file=network_map_json_path,
        output_dir=output_dir,
        drawio_filename=os.path.basename(drawio_filename),
        graphml_filename=os.path.basename(graphml_filename),
        layout_algo=layout_algo
    )

    print(f"Network discovery and mapping are complete. Outputs are saved in {output_dir}")
    return network_map
