import json
import os
import xml.sax.saxutils as saxutils
from N2G import drawio_diagram, yed_diagram
import xml.etree.ElementTree as ET

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

    with open("debug_node_data_processed.json", "w") as fh:
        fh.write(json.dumps(data, indent=2))

    return data

def set_organic_layout(input_file, output_file, spacing=400):
    """
    Phase 1: Apply organic layout with clean, simple edge styling

    Args:
        input_file (str): Path to input .drawio file
        output_file (str): Path to output .drawio file
        spacing (int): Spacing between nodes (default: 400)
    """
    try:
        tree = ET.parse(input_file)
        root = tree.getroot()

        # Find the mxGraphModel element
        graph_model = root.find(".//mxGraphModel")
        if graph_model is None:
            raise ValueError("No mxGraphModel found in the file")

        # Set larger canvas size
        graph_model.set('dx', '4000')
        graph_model.set('dy', '4000')
        graph_model.set('grid', '1')
        graph_model.set('gridSize', '10')

        # Find the root element
        root_element = graph_model.find("root")
        if root_element is not None:
            # Get the main parent cell (usually id="1")
            parent_cell = root_element.find("mxCell[@id='1']")
            if parent_cell is not None:
                # Set organic layout properties
                organic_style = (
                    "organic=1;"
                    f"organicSpacing={spacing};"
                    "animate=0;"
                    f"neighborSpacing={spacing};"
                    f"nodeSpacing={spacing};"
                    "parallelEdgeSpacing=100;"
                    "interRankCellSpacing=150;"
                    "interHierarchySpacing=100;"
                    "fineTuning=1"
                )
                parent_cell.set('style', organic_style)

            # Process all edges with minimal styling
            for edge in root_element.findall(".//mxCell[@edge='1']"):
                edge_style = (
                    "endArrow=none;"  # Remove arrows
                    "strokeWidth=1;"  # Thin lines
                    "html=1;"  # Required for proper rendering
                    "rounded=0;"  # No rounded corners
                    "jumpStyle=none"  # No jump marks
                )
                edge.set('style', edge_style)

            # Adjust vertex cells
            for vertex in root_element.findall(".//object/mxCell"):
                if vertex.get('vertex') == '1':
                    current_style = vertex.get('style', '')
                    style_dict = dict(item.split('=') for item in current_style.split(';') if '=' in item)
                    style_dict.update({
                        'spacing': str(spacing // 2),
                        'spacingTop': str(spacing // 4),
                        'spacingBottom': str(spacing // 4),
                        'rounded': '1'
                    })
                    new_style = ';'.join(f"{k}={v}" for k, v in style_dict.items())
                    vertex.set('style', new_style)

        # Save while maintaining uncompressed format
        tree.write(output_file, encoding='utf-8', xml_declaration=True)

        # Ensure compressed="false" is maintained
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()

        if 'compressed="false"' not in content:
            content = content.replace('<mxfile', '<mxfile compressed="false"')

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)

        return True

    except Exception as e:
        print(f"Error processing file: {str(e)}")
        return False

def create_network_diagrams(json_file, output_dir="./", drawio_filename="network_diagram.drawio",
                            graphml_filename="network_diagram.graphml", layout_algo="kk"):
    """
    Generate network diagrams from a JSON network map.

    :param json_file: Path to the JSON file containing the network data.
    :param output_dir: Directory to save the generated diagrams.
    :param drawio_filename: Name of the DrawIO file to create.
    :param graphml_filename: Name of the GraphML file to create.
    :param layout_algo: Graph layout algorithm to apply (e.g., "kk", "rt").
    """
    # Load JSON data from the provided file
    with open(json_file, 'r') as file:
        data = json.load(file)
        data = preprocess_data(data)

    with open(json_file + "_processed", "w") as fh:
        fh.write(json.dumps(data, indent=2))

    edges = set()

    # Initialize diagrams
    yed = yed_diagram()
    drawio = drawio_diagram()
    drawio.add_diagram("Page-1")

    # First pass - Add all nodes
    for node, info in data.items():
        if "unknown" not in node:
            node_details = info.get('node_details', {})
            top_label = node.strip()
            bottom_label = node_details.get('ip', 'Unknown IP').strip()

            # Add nodes to both diagrams
            yed.add_node(id=node, label=node)
            drawio.add_node(id=node, label=node)

    # Second pass - Add all links with unique edges
    for node, info in data.items():
        if "unknown" not in node:
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

    # Remove nodes not present in the data or labeled as "unknown"
    del_nodes = []
    for node_id in drawio.nodes_ids:
        if node_id in data:
            if "unknown" in node_id:
                del_nodes.append(node_id)
                continue
            node_details = data[node_id].get("node_details", {})
            top_label = node_id.strip()
            bottom_label = node_details.get("ip", "Unknown IP").strip()
            new_label = top_label + "\n" + bottom_label
            drawio.update_node(id=node_id, label=new_label)
        else:
            del_nodes.append(node_id)

    for node in del_nodes:
        try:
            drawio.delete_node(node)
        except Exception as e:
            print(f"Error deleting node {node}: {e}")

    # Similarly handle yEd nodes
    del_nodes = []
    for node_id in yed.nodes_ids:
        if node_id in data:
            if "unknown" in node_id:
                del_nodes.append(node_id)
                continue
            node_details = data[node_id].get("node_details", {})
            top_label = node_id.strip()
            bottom_label = node_details.get("ip", "Unknown IP").strip()
            new_label = top_label + "\n" + bottom_label
            yed.update_node(node_id, label=new_label)
        else:
            del_nodes.append(node_id)

    for node in del_nodes:
        try:
            yed.delete_node(node)
        except Exception as e:
            print(f"Error deleting node {node}: {e}")

    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Apply layout algorithm to yEd diagram and export as GraphML
    yed.layout(algo=layout_algo)
    yed.dump_file(filename=graphml_filename, folder=output_dir)

    # Apply layout algorithm to DrawIO diagram and export
    drawio.layout(algo=layout_algo)
    drawio.dump_file(filename=drawio_filename, folder=output_dir)
    drawio_path = os.path.join(output_dir, drawio_filename)
    success = set_organic_layout(drawio_path, drawio_path)
    print(f"Organic Layout Applied Successfully? {success}")
