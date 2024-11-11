import os
import json


def merge_maps(basefolder, output):
    """
    Merges JSON map files located in the "map" subfolder within each site folder.

    Args:
        basefolder (str): Top-level directory containing site folders, each with
                          a "map" subfolder containing JSON map files.
        output (str): Path to save the merged output map file.

    Raises:
        ValueError: If basefolder does not exist or contains no valid JSON files.
    """
    if not os.path.exists(basefolder):
        raise ValueError(f"The base folder {basefolder} does not exist.")

    combined_data = {}

    # Traverse site folders within the base folder
    for site_folder in os.listdir(basefolder):
        site_folder_path = os.path.join(basefolder, site_folder)
        print(f"Debug: Checking site folder: {site_folder_path}")

        if not os.path.isdir(site_folder_path):
            continue  # Skip non-directory entries

        # Look specifically for the "map" subfolder within each site folder
        map_folder_path = os.path.join(site_folder_path, "map")
        if not os.path.isdir(map_folder_path):
            print(f"Debug: No 'map' folder found in {site_folder_path}. Skipping...")
            continue

        # Process JSON files within the "map" subfolder
        for file_name in os.listdir(map_folder_path):
            if file_name.endswith('.json'):
                file_path = os.path.join(map_folder_path, file_name)
                process_json_file(file_path, combined_data)

    if not combined_data:
        raise ValueError(f"No valid JSON map files found in {basefolder} or its subdirectories.")

    # Write merged data to the output file
    with open(output, 'w') as out_file:
        json.dump(combined_data, out_file, indent=2)
    print(f"Debug: Merged map saved to {output}")


def process_json_file(file_path, combined_data):
    """
    Processes a JSON file and merges its contents into the combined data.

    Args:
        file_path (str): Path to the JSON file.
        combined_data (dict): Dictionary to merge the JSON data into.
    """
    print(f"Debug: Processing JSON file at {file_path}")
    try:
        with open(file_path, 'r') as json_file:
            file_data = json.load(json_file)

            # Handle if file_data is a dictionary
            if isinstance(file_data, dict):
                merge_data(file_data, combined_data)

            # Handle if file_data is a list
            elif isinstance(file_data, list):
                for item in file_data:
                    if isinstance(item, dict):
                        merge_data(item, combined_data)
                    else:
                        print(f"Skipping non-dictionary item in list: {item}")

            else:
                print(f"Skipping unsupported JSON format in {file_path}")

    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Skipping {file_path}: {e}")


def merge_data(data, combined_data):
    """
    Merges a single JSON data dictionary into the combined data.

    Args:
        data (dict): JSON data to merge.
        combined_data (dict): Dictionary to merge the JSON data into.
    """
    for node, details in data.items():
        if node in combined_data:
            if combined_data[node]['node_details'] != details['node_details']:
                combined_data[node]['node_details'].update(details['node_details'])

            for peer, peer_details in details['peers'].items():
                if peer in combined_data[node]['peers']:
                    for connection in peer_details['connections']:
                        if connection not in combined_data[node]['peers'][peer]['connections']:
                            combined_data[node]['peers'][peer]['connections'].append(connection)
                else:
                    combined_data[node]['peers'][peer] = peer_details
        else:
            combined_data[node] = details
