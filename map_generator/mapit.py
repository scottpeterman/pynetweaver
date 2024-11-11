import click
import os
import json
from datetime import datetime
from map_generator.discovery_coordinator import DiscoveryCoordinator
from map_generator.mapping_tools import create_network_diagrams



@click.command()
@click.option('--seed_ip', help='Seed IP address to start the discovery process.')
@click.option('--device_ip', help='Device IP address to start the discovery process.')
@click.option('--username', help='Username for device authentication.')
@click.option('--password', help='Password for device authentication.')
@click.option('--vendor', type=click.Choice(['cisco', 'arista', 'aruba']), help='Device vendor (cisco, arista, aruba).')
@click.option('--protocol', type=click.Choice(['cdp', 'lldp']), help='Discovery protocol to use (cdp or lldp).')
@click.option('--domain_name', default='home.com', help='Domain name to strip from device hostnames.')
@click.option('--exclude_string', default='', help='Comma-separated string of devices to exclude (e.g., SEP,VMWare).')
@click.option('--map_name', default='network_map', help='Prefix name for the output map files.')
@click.option('--layout_algo', default='rt', help='Graph layout algorithm to use (e.g., rt, kk).')
@click.option('--output_dir', default='./output', help='Root directory where the results will be saved.')
def main(seed_ip, device_ip, username, password, vendor, protocol, domain_name, exclude_string, map_name, layout_algo, output_dir):
    # Validate the input
    if not seed_ip and not device_ip:
        raise click.UsageError("Either --seed_ip or --device_ip must be provided.")

    # Create the subdirectory within the output directory using the map name
    map_output_dir = os.path.join(output_dir, map_name)
    if not os.path.exists(map_output_dir):
        os.makedirs(map_output_dir)

    # Construct file names with the prefix
    graphml_filename = f"{map_name}.graphml"
    drawio_filename = f"{map_name}.drawio"
    json_filename = f"{map_name}.json"

    # Seed device configuration
    seed_device = {
        'ip': seed_ip or device_ip,
        'username': username,
        'password': password,
        'vendor': vendor,
        'protocol': protocol,
        'domain_name': domain_name,
        'output_dir': map_output_dir,
        'node_details': {"ip": seed_ip or device_ip, "platform": vendor}
    }

    # Initialize the discovery coordinator
    coordinator = DiscoveryCoordinator(seed_device, exclude_string, graphml_filename, drawio_filename, layout_algo)

    # Execute the discovery process and retrieve the network map
    network_map = coordinator.discover()

    # Save the network map as a JSON file
    network_map_json_path = os.path.join(map_output_dir, json_filename)
    with open(network_map_json_path, 'w') as json_file:
        json.dump(network_map, json_file, indent=2)

    # Create network diagrams
    create_network_diagrams(json_file=network_map_json_path, output_dir=map_output_dir,
                            drawio_filename=drawio_filename, graphml_filename=graphml_filename, layout_algo=layout_algo)

    print(f"Network discovery and mapping are complete. Outputs are saved in {map_output_dir}.")

if __name__ == '__main__':
    main()
