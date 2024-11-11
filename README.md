# PyNetWeaver

**PyNetWeaver** is a powerful network discovery and data collection tool designed to gather information from multi-vendor network environments using both SNMP and SSH protocols. It supports various network devices, including Cisco (IOS, NX-OS), Arista (EOS), Aruba (ArubaOS), and Palo Alto (PAN-OS). The tool uses a combination of SNMP and CLI commands, leveraging TTP templates for efficient parsing of network device outputs.

## Key Features

- **Multi-Vendor Support**: Seamless data collection from devices running Cisco IOS, NX-OS, Arista EOS, ArubaOS, and Palo Alto PAN-OS.
- **Dual Protocols**: Supports both SNMP (v2/v3) and SSH for comprehensive data gathering, with automatic fallback to SSH if SNMP fails.
- **Template-Based Parsing**: Uses the TTP library for consistent and efficient parsing of command outputs.
- **Breadth-First Search (BFS) Network Discovery**: Crawls the network starting from a seed IP, exploring neighbors via CDP and LLDP.
- **Data Export**: Exports collected data to JSON and CSV formats, including a detailed summary of discovered devices.
- **Configurable via YAML**: All credentials (SSH and SNMP) are managed through a YAML configuration file (`creds.yaml`).
- **Logging and Error Handling**: Detailed logging for easier troubleshooting, with graceful error handling and retry mechanisms.

## Project Structure

```
pynetweaver/
├── compiled_mibs/           # Directory for pre-compiled MIBs
├── templates/               # TTP parsing templates for various commands
├── creds.yaml               # YAML file for storing SSH and SNMP credentials
├── network_discovery.log    # Log file for discovery process
├── ds2_network_discovery.json # Default JSON output file for collected data
├── network_discovery_summary.csv # Default CSV summary file
├── pynw_cli.py              # Main application script
├── README.md                # Project documentation (this file)
```

## Prerequisites

Ensure you have the following installed:

- **Python 3.8+**
- **PySSHPass** (for SSH interactions)
- **TTPFire** (for TTP parsing engine)
- **FuncTimeout** (for handling timeouts)
- **hnmp** (for SNMP interactions)
- **PyYAML** (for YAML configuration parsing)
- **PySNMP** (for SNMP protocol support)

You can install all required packages using:

```bash
pip install -r requirements.txt
```

## Configuration

The `creds.yaml` file holds the credentials for SNMP and SSH access across different vendor devices. An example configuration is provided below:

### Example `creds.yaml`

```yaml
default:
  ssh_username: "cisco"
  ssh_password: "cisco"
  enable_password: "cisco"
  snmp_communities:
    - "public"
    - "private"

arista:
  username: "admin"
  password: "admin"
  enable: "admin"

aruba:
  username: "admin"
  password: "password"
  enable: "enable"

paloalto:
  username: "admin"
  password: "admin"

snmpv3:
  username: "snmpv3_user"
  authproto: "sha"
  authkey: "auth_key"
  privproto: "aes128"
  privkey: "priv_key"
```

- **default**: Default credentials used for most devices.
- **arista, aruba, paloalto**: Specific credentials for Arista, Aruba, and Palo Alto devices.
- **snmpv3**: SNMPv3 credentials (username, authentication, and privacy settings).

## How to Run

### Basic Usage

The script can be executed from the command line using `click`:

```bash
python pynw_cli.py --ip <seed_ip_address> --output-json <output_file.json> --output-csv <summary_file.csv> --creds-file <creds.yaml>
```

### Example Command

```bash
python pynw_cli.py --ip 192.168.1.1 --output-json discovery_results.json --output-csv discovery_summary.csv --creds-file creds.yaml
```

### Command-Line Options

- `--ip`: **(Required)** Seed IP address to start network discovery.
- `--output-json`: Path to save the JSON output file (default: `ds2_network_discovery.json`).
- `--output-csv`: Path to save the CSV summary file (default: `network_discovery_summary.csv`).
- `--creds-file`: Path to the YAML file with credentials (default: `creds.yaml`).

## Example Output

### JSON Output

The JSON file contains detailed information about each discovered device, including access information and collected data:

```json
{
  "timestamp": "2024-11-10T10:27:23",
  "devices": {
    "usa1-access-02": {
      "ip_address": "172.16.101.4",
      "access_info": {
        "ssh_works": true,
        "snmp_works": true,
        "working_community": "public",
        "os_type": "ios",
        "prompt": "usa1-access-02#",
        "hostname": "usa1-access-02"
      },
      "collected_data": {
        "version": {
          "software_version": "15.2(4.0.55)E"
        },
        "cdp-detail": {
          "device_id": "usa1-rtr-1",
          "ip_address": "172.16.101.100",
          "platform": "Cisco 7206VXR",
          "capabilities": "Router"
        }
      },
      "collection_errors": [],
      "discovery_time": "2024-11-10T10:25:00"
    }
  },
  "summary": {
    "total_devices": 10,
    "snmp_accessible": 8,
    "ssh_accessible": 7,
    "os_types": {
      "ios": 5,
      "nxos": 2,
      "arista": 2,
      "unknown": 1
    },
    "failed_devices": [],
    "discovery_duration": "0:05:00"
  }
}
```

### CSV Summary

The CSV summary file provides a concise overview of the discovered devices:

```csv
Device ID,IP Address,SSH Status,SNMP Status,OS Type,Error Count,Discovery Time
usa1-access-02,172.16.101.4,True,True,ios,0,2024-11-10T10:25:00
usa1-rtr-1,172.16.101.100,True,True,ios,0,2024-11-10T10:25:30
```

## Logging

All logs are written to `network_discovery.log` with detailed information about the discovery process, including errors and warnings.

```log
2024-11-10 10:27:23,023 - INFO - Starting network discovery...
2024-11-10 10:27:25,567 - DEBUG - Attempting SNMP collection for IP: 172.16.101.4
2024-11-10 10:27:28,234 - INFO - Successfully collected SNMP data for IP: 172.16.101.4
2024-11-10 10:28:10,789 - WARNING - SSH collection failed for IP: 172.16.101.200
2024-11-10 10:30:00,012 - INFO - Network discovery completed in 5 minutes
```

## Troubleshooting

- **Credentials Not Working**: Ensure the `creds.yaml` file has the correct credentials and access permissions.
- **SNMP Collection Fails**: Verify that SNMP is enabled on the devices and the correct communities are specified.
- **SSH Timeout Issues**: Increase the timeout values in `SSHClientWrapper` if connections are timing out frequently.
- **Parsing Errors**: Check the TTP templates in the `templates/` directory for any mismatches with the device output format.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

