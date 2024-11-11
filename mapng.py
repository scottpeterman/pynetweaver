import pprint
import yaml
import click
from mapit import run_discovery
from merge_maps import merge_maps


def load_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    return config


@click.command()
@click.argument('job_yaml_file', type=click.Path(exists=True))
def main(job_yaml_file):
    """
    Run network discovery and map merge based on a YAML configuration file.

    CONFIG_FILE is the path to the YAML file containing discovery and merge configurations.
    """
    config = load_config(job_yaml_file)

    # Check if discovery is a list and iterate over each configuration
    discovery_list = config.get('discovery', [])
    if isinstance(discovery_list, list):
        for index, discovery_config in enumerate(discovery_list):
            print(f"Starting discovery job {index + 1}")
            pprint.pprint(discovery_config)

            # Execute run_discovery with parameters from each configuration
            run_discovery(
                seed_ip=discovery_config.get('seed_ip'),
                device_ip=discovery_config.get('device_ip'),
                username=discovery_config.get('username'),
                password=discovery_config.get('password'),
                vendor=discovery_config.get('vendor'),
                protocol=discovery_config.get('protocol'),
                domain_name=discovery_config.get('domain_name'),
                exclude_string=discovery_config.get('exclude_string'),
                map_name=discovery_config.get('map_name'),
                layout_algo=discovery_config.get('layout_algo'),
                output_dir=discovery_config.get('output_dir')
            )

            print(f"Discovery job {index + 1} complete.")

        print("All network discovery jobs complete.")

    print("-" * 30)
    print("Phase 2 - merge maps")

    # Phase 2: Merge Maps
    merge_config = config.get('merge')
    if merge_config:
        print("Starting map merge phase")
        pprint.pprint(merge_config)

        merge_maps(
            basefolder=merge_config.get('basefolder'),
            output=merge_config.get('output')
        )

        print("Map merging complete. \nUse map_json.py to generate graphml and drawio maps\nfind you xxx_merged_maps.json")
        print('''example: python map_json.py -json usp_merged_maps.json -o "./generated_maps" -n use''')
    else:
        print("No merge configuration found. Skipping merge phase.")


if __name__ == '__main__':
    main()
