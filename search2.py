from flask import Flask, jsonify, request, render_template
import json
import jmespath
import re
import os

app = Flask(__name__)

# Global variable to hold the JSON data
data = None

# Directory containing the JSON files
JSON_DIRECTORY = './pynetweaver_data'


def load_json_file(filename):
    """Load the specified JSON file."""
    global data
    try:
        with open(os.path.join(JSON_DIRECTORY, filename), 'r') as file:
            data = json.load(file)
        print(f"Loaded data from {filename}")
        return True
    except Exception as e:
        print(f"Error loading JSON file: {str(e)}")
        return False


def is_ip_address(query):
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return bool(ip_pattern.match(query))


def is_mac_address(query):
    mac_patterns = [
        re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'),
        re.compile(r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$')
    ]
    return any(pattern.match(query) for pattern in mac_patterns)


def normalize_mac_address(mac):
    mac = re.sub('[.:-]', '', mac.lower())
    return ':'.join(mac[i:i + 2] for i in range(0, 12, 2))


def search_device(query):
    query = query.strip()
    if not data:
        return None

    try:
        jmespath_query = str(f"""
        devices.* | [? contains(collected_data.snmp.system.sysName, '{query}') || 
                     contains(access_info.prompt || '', '{query}') ||
                     contains(access_info.hostname || '', '{query}')]
        """).strip()

        results = jmespath.search(jmespath_query, data)

        matched_devices = []
        if results:
            for device_name, device_data in data['devices'].items():
                if device_data in results:
                    device_data['name'] = device_name
                    matched_devices.append(device_data)

        return matched_devices if matched_devices else None

    except jmespath.exceptions.JMESPathError as e:
        print(f"JMESPath error: {str(e)}")
        return None


@app.route('/')
def index():
    """Render the file selection interface."""
    files = os.listdir(JSON_DIRECTORY)
    json_files = [f for f in files if f.endswith('.json')]
    return render_template('search2.html', json_files=json_files)


@app.route('/load', methods=['POST'])
def load_file():
    """Handle the JSON file selection."""
    filename = request.form.get('filename')
    if not filename:
        return jsonify({'error': 'No file selected'}), 400

    if load_json_file(filename):
        return jsonify({'message': f'Successfully loaded {filename}'})
    else:
        return jsonify({'error': 'Failed to load the file'}), 500


@app.route('/search')
def search():
    """Handle search requests."""
    query = request.args.get('query', '').strip()

    if not query:
        return jsonify({'error': 'No search query provided'}), 400

    results = search_device(query)
    if results:
        return jsonify({'devices': results})

    return jsonify({'error': 'No matching devices found'}), 404


@app.route('/json-files', methods=['GET'])
def list_json_files():
    """Return a list of available JSON files in the json_files directory."""
    try:
        files = os.listdir(JSON_DIRECTORY)
        json_files = [f for f in files if f.endswith('.json')]
        return jsonify(json_files), 200
    except Exception as e:
        print(f"Error listing JSON files: {str(e)}")
        return jsonify({'error': 'Failed to list JSON files'}), 500


@app.route('/load-json', methods=['POST'])
def load_json():
    """Load the selected JSON file into memory."""
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400

    if load_json_file(filename):
        return jsonify({'message': f'Successfully loaded {filename}'}), 200
    else:
        return jsonify({'error': f'Failed to load the file: {filename}'}), 500


if __name__ == '__main__':
    app.run(debug=True)
