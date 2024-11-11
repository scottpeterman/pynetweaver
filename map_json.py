import argparse
import json
import os
import xml.sax.saxutils as saxutils
from N2G import drawio_diagram, yed_diagram
import logging

logger = logging.getLogger(__name__)


def strip_domain(node_id):
    """Utility to strip the domain part of the node identifier."""
    return node_id.split('.')[0]


def preprocess_data(data):
    """Process the network data to enrich node_details using discovered CDP data from peers."""
    node_details_map = {}

    # First pass: Collect detailed info from peers
    for node, info in data.items():
        node_details = info.get('node_details', {})
        if node_details.get('ip') == 'Unknown':
            # Check all nodes to find matching peer details
            for check_node, check_info in data.items():
                for peer_id, peer_info in check_info.get('peers', {}).items():
                    if peer_id == node:
                        node_details_map[node] = {
                            'ip': peer_info.get('ip'),
                            'platform': peer_info.get('platform')
                        }

    # Second pass: Update top-level nodes with enhanced details from peers if they're more informative
    for node, info in data.items():
        node_details = info.get('node_details', {})
        if node in node_details_map:
            better_details = node_details_map[node]
            if better_details.get('ip') != 'Unknown':
                node_details['ip'] = better_details['ip']
            if better_details.get('platform') != 'Unknown Platform':
                node_details['platform'] = better_details['platform']
        data[node]['node_details'] = node_details

    return data


def create_network_diagrams(json_file, output_dir, map_name, layout_algo="kk"):
    """
    Generate network diagrams from a JSON network map.

    :param json_file: Path to the JSON file containing the network data.
    :param output_dir: Directory to save the generated diagrams.
    :param map_name: Name of the output map.
    :param layout_algo: Graph layout algorithm to apply (e.g., "kk", "rt").
    """
    drawio_filename = f"{map_name}.drawio"
    graphml_filename = f"{map_name}.graphml"

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Load JSON data from the provided file
    with open(json_file, 'r') as file:
        data = json.load(file)
        data = preprocess_data(data)

    # Save the processed data (optional step)
    processed_json_path = os.path.join(output_dir, f"{map_name}_processed.json")
    with open(processed_json_path, "w") as fh:
        json.dump(data, fh, indent=2)

    edges = set()

    # Initialize diagrams
    yed = yed_diagram()
    drawio = drawio_diagram()
    drawio.add_diagram("Page-1")

    # First pass - Add all nodes
    for node, info in data.items():
        if "unknown" not in node.lower():
            node_details = info.get('node_details', {})
            top_label = node.strip()
            bottom_label = node_details.get('ip', 'Unknown IP').strip()

            # Add nodes to both diagrams
            yed.add_node(id=node, label=top_label)
            drawio.add_node(id=node, label=top_label)

    # Second pass - Add all links with unique edges
    for node, info in data.items():
        if "unknown" not in node.lower():
            for peer_id, peer_info in info.get('peers', {}).items():
                for connection in peer_info.get('connections', []):
                    local_port, remote_port = connection
                    edge_key = (node, peer_id, local_port, remote_port)

                    if edge_key not in edges:
                        edges.add(edge_key)

                        # Add connection to yEd with source and target labels
                        yed.add_link(
                            source=node,
                            target=peer_id,
                            src_label=saxutils.escape(local_port),
                            trgt_label=saxutils.escape(remote_port)
                        )

                        # Add connection to DrawIO with source and target labels
                        drawio.add_link(
                            source=node,
                            target=peer_id,
                            src_label=saxutils.escape(local_port),
                            trgt_label=saxutils.escape(remote_port)
                        )

    # Apply layout algorithm to yEd diagram and export as GraphML
    yed.layout(algo=layout_algo)
    yed.dump_file(filename=graphml_filename, folder=output_dir)

    # Apply layout algorithm to DrawIO diagram and export
    drawio.layout(algo=layout_algo)
    drawio.dump_file(filename=drawio_filename, folder=output_dir)


def main():
    parser = argparse.ArgumentParser(description="Generate network diagrams from a JSON file.")
    parser.add_argument('-json', '--json-file', required=True, help='Path to the input JSON file')
    parser.add_argument('-o', '--output-dir', required=True, help='Directory to write output files')
    parser.add_argument('-n', '--map-name', required=True, help='Name for the generated map (used for file names)')

    args = parser.parse_args()

    create_network_diagrams(
        json_file=args.json_file,
        output_dir=args.output_dir,
        map_name=args.map_name
    )


if __name__ == "__main__":
    main()
# netdisco/ush_merged.json