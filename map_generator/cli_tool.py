import subprocess
import logging
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.FATAL, format='%(asctime)s - %(levelname)s - %(message)s')

def run_cli_tool(seed_ip, device_ip, username, password, vendor, protocol, domain_name, exclude_string, map_name, layout_algo, output_dir):
    command = [sys.executable, "mapit.py"]

    if seed_ip:
        command.extend(["--seed_ip", seed_ip])
    if device_ip:
        command.extend(["--device_ip", device_ip])
    if username:
        command.extend(["--username", username])
    if password:
        command.extend(["--password", password])
    if vendor:
        command.extend(["--vendor", vendor])
    if protocol:
        command.extend(["--protocol", protocol])
    if domain_name:
        command.extend(["--domain_name", domain_name])
    if exclude_string:
        command.extend(["--exclude_string", exclude_string])
    if map_name:
        command.extend(["--map_name", map_name])
    if layout_algo:
        command.extend(["--layout_algo", layout_algo])
    if output_dir:
        command.extend(["--output_dir", output_dir])

    map_generator_dir = Path(__file__).parent  # Assuming this script is in the same directory as mapit.py
    logging.debug(f"Running command: {command} \nfrom {map_generator_dir}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, cwd=map_generator_dir)

    for stdout_line in iter(process.stdout.readline, ""):
        logging.debug(f"Output: {stdout_line.strip()}")
        yield stdout_line
    process.stdout.close()

    return_code = process.wait()
    if return_code:
        logging.error(f"Command failed with return code {return_code}")
        raise subprocess.CalledProcessError(return_code, command)

# Example usage
if __name__ == "__main__":
    try:
        for output in run_cli_tool(
            seed_ip="172.16.101.100",
            device_ip=None,
            username="cisco",
            password="cisco",
            vendor="cisco",
            protocol="cdp",
            domain_name=".home.com",
            exclude_string="SEP",
            map_name="Network_map.graphml",
            layout_algo="rt",
            output_dir="./output"
        ):
            print(output, end="")
    except subprocess.CalledProcessError as e:
        logging.error("An error occurred while running the CLI tool.")
