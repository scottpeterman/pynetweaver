from flask import Flask, jsonify, request, render_template
import json
import jmespath
import re

app = Flask(__name__)

# Load JSON data once at startup
with open('usa.json', 'r') as file:
    data = json.load(file)


def is_ip_address(query):
    """Check if the query is an IP address."""
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return bool(ip_pattern.match(query))


def is_mac_address(query):
    """Check if the query is a MAC address."""
    # Support multiple MAC address formats (xx:xx:xx:xx:xx:xx, xx-xx-xx-xx-xx-xx, xxxx.xxxx.xxxx)
    mac_patterns = [
        re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'),
        re.compile(r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$')
    ]
    return any(pattern.match(query) for pattern in mac_patterns)


def normalize_mac_address(mac):
    """Normalize MAC address format to xx:xx:xx:xx:xx:xx."""
    # Remove all separators and convert to lowercase
    mac = re.sub('[.:-]', '', mac.lower())
    # Insert colons
    return ':'.join(mac[i:i + 2] for i in range(0, 12, 2))


def search_device(query):
    """
    Search function that looks for matches across multiple fields using a validated JMESPath query
    and returns all relevant data for matched devices.
    """
    query = query.strip()
    try:
        # Use the validated JMESPath query for partial name search
        jmespath_query = str(f"""
        devices.* | [? contains(collected_data.snmp.system.sysName, '{query}') || 
                     contains(access_info.prompt || '', '{query}') ||
                     contains(access_info.hostname || '', '{query}')]
        """).strip()

        # Execute the JMESPath query and get all matches
        results = jmespath.search(jmespath_query, data)

        # Prepare the list of matched devices
        matched_devices = []
        if results:
            for device_name, device_data in data['devices'].items():
                # Check if the current device data is in the JMESPath results
                if device_data in results:
                    # Add the top-level device name to the device data
                    device_data['name'] = device_name
                    matched_devices.append(device_data)

        # Return the list of matched devices or None if no matches found
        print(f"Found {len(matched_devices)} devices")
        return matched_devices if matched_devices else None

    except jmespath.exceptions.JMESPathError as e:
        print(f"JMESPath error: {str(e)}")
        return None


def fallback_search(query):
    """
    Fallback search method that uses direct dictionary access instead of JMESPath
    when dealing with problematic keys.
    """
    results = []
    for device_name, device_data in data['devices'].items():
        # Check IP address
        if device_data.get('ip_address') == query:
            device_data['name'] = device_name
            results.append(device_data)
            continue

        # Check ARP table
        arp_entries = device_data.get('collected_data', {}).get('cli', {}).get('arp', [])
        for entry in arp_entries:
            if entry.get('ip_address') == query or entry.get('mac_address') == query:
                device_data['name'] = device_name
                results.append(device_data)
                break

        # Check CDP neighbors
        cdp_entries = device_data.get('collected_data', {}).get('cli', {}).get('cdp-detail', [])
        for entry in cdp_entries:
            if entry.get('ip_address') == query:
                device_data['name'] = device_name
                results.append(device_data)
                break

        # Check LLDP neighbors
        lldp_entries = device_data.get('collected_data', {}).get('cli', {}).get('lldp-detail', [])
        for entry in lldp_entries:
            if entry.get('ip_address') == query:
                device_data['name'] = device_name
                results.append(device_data)
                break

        # Check device name and hostname
        if query.lower() in device_name.lower():
            device_data['name'] = device_name
            results.append(device_data)
            continue

        hostname = device_data.get('access_info', {}).get('hostname')
        if hostname and query.lower() in hostname.lower():
            device_data['name'] = device_name
            results.append(device_data)

    return results if results else None


@app.route('/')
def index():
    """Render the search interface."""
    return render_template('index4.html')


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

if __name__ == '__main__':
    app.run(debug=True)
