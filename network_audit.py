import subprocess
import logging
import sys
import importlib
import getpass
import os
import re
import hashlib
import base64

# Configure logging
logging.basicConfig(filename='audit_network.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
NC = '\033[0m'  # No Color

ssh_client = None


def check_and_install_dependencies():
    dependencies = ['tabulate', 'paramiko']
    for package in dependencies:
        try:
            importlib.import_module(package)
            print(f"{GREEN}{package} is already installed.{NC}")
        except ImportError:
            print(f"{YELLOW}{package} is not installed. Attempting to install...{NC}")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"{GREEN}{package} has been successfully installed.{NC}")
            except subprocess.CalledProcessError:
                print(f"{RED}Failed to install {package}. Please install it manually.{NC}")
                sys.exit(1)

    global tabulate, paramiko
    import paramiko
    import tabulate


check_and_install_dependencies()


def execute_command(command, remote=False):
    try:
        if remote and ssh_client:
            if isinstance(command, list):
                command = ' '.join(command)
            stdin, stdout, stderr = ssh_client.exec_command(command)
            return stdout.read().decode('utf-8')
        else:
            if isinstance(command, str):
                command = command.split()
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result.stdout
    except (subprocess.CalledProcessError, paramiko.SSHException) as e:
        error_msg = f"Error executing {command}: {str(e)}"
        logging.error(error_msg)
        return error_msg


def list_interfaces(remote=False):
    print(f"\n{BLUE}Network interfaces and their status:{NC}")
    interfaces = execute_command(["ip", "-br", "link", "show"], remote)
    table = []
    for line in interfaces.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            state = f"{GREEN}{parts[1]}{NC}" if parts[1] == "UP" else f"{RED}{parts[1]}{NC}"
            table.append([parts[0], state])
    print(tabulate.tabulate(table, headers=["Interface", "Status"], tablefmt="grid"))
    logging.info("Listed network interfaces")


def show_ip_addresses(remote=False):
    print(f"\n{BLUE}IP addresses assigned to each interface:{NC}")
    ips = execute_command(["ip", "-br", "addr", "show"], remote)
    table = []
    for line in ips.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            table.append([parts[0], f"{YELLOW}{parts[2]}{NC}"])
    print(tabulate.tabulate(table, headers=["Interface", "IP Address"], tablefmt="grid"))
    logging.info("IP addresses displayed")


def show_routing_table(remote=False):
    print(f"\n{BLUE}Current routing table:{NC}")
    routes = execute_command(["ip", "route", "show"], remote)
    table = []
    for line in routes.splitlines():
        table.append([f"{GREEN}{line}{NC}"])
    print(tabulate.tabulate(table, headers=["Route"], tablefmt="grid"))
    logging.info("Routing table shown")


def show_firewall_rules(remote=False):
    print(f"\n{BLUE}Firewall (UFW) rules:{NC}")
    try:
        rules = execute_command(["sudo", "ufw", "status", "numbered"], remote)
        table = []
        for line in rules.splitlines():
            if line.startswith("["):
                table.append([f"{YELLOW}{line}{NC}"])
        print(tabulate.tabulate(table, headers=["UFW Rule"], tablefmt="grid"))
        logging.info("Firewall rules displayed")
    except FileNotFoundError:
        error_msg = "Error: UFW is not installed on this system."
        print(f"{RED}{error_msg}{NC}")
        logging.error(error_msg)


def list_open_connections(remote=False):
    print(f"\n{BLUE}Some open network connections:{NC}")
    connections = execute_command(["ss", "-tuln"], remote)
    table = []
    for line in connections.splitlines()[1:]:  # Omit first line (header)
        parts = line.split()
        if len(parts) >= 5:
            table.append([f"{GREEN}{parts[0]}{NC}", f"{YELLOW}{parts[4]}{NC}", f"{YELLOW}{parts[5]}{NC}"])
    print(tabulate.tabulate(table, headers=["State", "Local Address", "Remote Address"], tablefmt="grid"))
    logging.info("Open network connections listed")


def list_docker_nets(remote=False):
    print(f"\n{BLUE}Docker Networks:{NC}")
    found = execute_command(['which', 'docker'], remote)
    if 'docker' not in found:
        print(f"{RED}Docker not found.{NC}")
        return
    nets = execute_command(['docker', 'network', 'ls'], remote)
    table = []
    for line in nets.splitlines()[1:]:
        net = line.split()
        if len(net) >= 4:
            netname = net[1]
            table.append([f"{GREEN}{netname}{NC}", f"", f""])
            inspect_output = execute_command(['docker', 'inspect', netname], remote)
            p2 = subprocess.Popen(['egrep', 'Name|IPv4'], text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, _ = p2.communicate(input=inspect_output)
            hostname = ""
            hostip = ""
            for host in stdout.splitlines()[1:]:
                host = host.split(':')
                if len(host) >= 2:
                    s = host[0].split('"')[1]
                    t = host[1].split('"')[1]
                    if s == 'Name':
                        hostname = t
                    if s == 'IPv4Address':
                        hostip = t
                        table.append([f"", f"{YELLOW}{hostname}{NC}", f"{YELLOW}{hostip}{NC}"])
    print(tabulate.tabulate(table, headers=["Network Name", "Host Name", "Host IP"], tablefmt="grid"))
    logging.info("Docker network connections listed")


def print_menu():
    print(f"\n{GREEN}Network Configuration Audit Menu:{NC}")
    print("1. List network interfaces")
    print("2. Show IP addresses")
    print("3. Show routing table")
    print("4. Show firewall rules")
    print("5. List open network connections")
    print("6. List Docker networks")
    print("7. Run all checks")
    print("8. Exit")


def load_ssh_key(key_path, key_password=None):
    try:
        return paramiko.RSAKey.from_private_key_file(key_path, password=key_password)
    except paramiko.ssh_exception.SSHException:
        try:
            return paramiko.DSSKey.from_private_key_file(key_path, password=key_password)
        except paramiko.ssh_exception.SSHException:
            try:
                return paramiko.ECDSAKey.from_private_key_file(key_path, password=key_password)
            except paramiko.ssh_exception.SSHException:
                return paramiko.Ed25519Key.from_private_key_file(key_path, password=key_password)


def verify_host_key(hostname, key):
    known_hosts_path = os.path.expanduser('~/.ssh/known_hosts')
    try:
        host_keys = paramiko.HostKeys(known_hosts_path)
        if hostname in host_keys:
            if host_keys[hostname].get(key.get_name()) == key:
                return True
    except IOError:
        print(f"Warning: {known_hosts_path} does not exist.")

    fingerprint = key.get_fingerprint().hex(':')
    sha256_fingerprint = hashlib.sha256(key.asbytes()).digest()
    sha256_fingerprint = base64.b64encode(sha256_fingerprint).decode('ascii').rstrip('=')

    print(f"The authenticity of host '{hostname}' can't be established.")
    print(f"{key.get_name()} key fingerprint is SHA256:{sha256_fingerprint}")
    print(f"This host key is not known by any other names")
    response = input(f"Are you sure you want to continue connecting (yes/no/[fingerprint])? ").lower()

    if response == 'yes' or response == sha256_fingerprint:
        with open(known_hosts_path, 'a') as f:
            f.write(f"{hostname} {key.get_name()} {key.get_base64()}\n")
        print(f"Warning: Permanently added '{hostname}' ({key.get_name()}) to the list of known hosts.")
        return True
    return False


def handle_unknown_host_key(hostname, username, key):
    fingerprint = key.get_fingerprint().hex(':')
    sha256_fingerprint = hashlib.sha256(key.asbytes()).digest()
    sha256_fingerprint = base64.b64encode(sha256_fingerprint).decode('ascii').rstrip('=')

    print(f"The authenticity of host '{hostname} ({hostname})' can't be established.")
    print(f"{key.get_name().upper()} key fingerprint is SHA256:{sha256_fingerprint}")
    print("This key is not known by any other names")
    response = input("Are you sure you want to continue connecting (yes/no/[fingerprint])? ").lower()

    if response == 'yes' or response == sha256_fingerprint:
        known_hosts_path = os.path.expanduser('~/.ssh/known_hosts')
        with open(known_hosts_path, 'a') as f:
            f.write(f"{hostname} {key.get_name()} {key.get_base64()}\n")
        print(f"Warning: Permanently added '{hostname}' ({key.get_name()}) to the list of known hosts.")
        return True
    return False


def validate_hostname(hostname):
    if re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        return hostname
    else:
        raise ValueError("Invalid hostname. Only alphanumeric characters, dots, and hyphens are allowed.")


def connect_ssh(hostname, timeout=10):
    global ssh_client
    ssh_client = paramiko.SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy())

    username = input("Enter SSH username: ")

    try:
        ssh_client.connect(hostname, username=username, allow_agent=True, look_for_keys=True, timeout=timeout)

        transport = ssh_client.get_transport()
        remote_key = transport.get_remote_server_key()
        if not verify_host_key(hostname, remote_key):
            print("Host key verification failed. Aborting connection.")
            ssh_client.close()
            sys.exit(1)

        print(f"{GREEN}Successfully connected to {hostname} using SSH agent.{NC}")
        logging.info(f"SSH connection established to {hostname} using SSH agent")
        return
    except paramiko.SSHException as e:
        if "Unknown server" in str(e):
            key = ssh_client.get_transport().get_remote_server_key()
            if handle_unknown_host_key(hostname, username, key):
                ssh_client.connect(hostname, username=username, allow_agent=True, look_for_keys=True, timeout=timeout)
                print(f"{GREEN}Successfully connected to {hostname} using SSH agent.{NC}")
                logging.info(f"SSH connection established to {hostname} using SSH agent")
                return
        print(f"Unable to connect using SSH agent: {str(e)}. Trying other methods...")

    auth_method = input("Choose authentication method (password/key): ").lower()

    if auth_method == 'password':
        password = getpass.getpass("Enter SSH password: ")
        try:
            ssh_client.connect(hostname, username=username, password=password, timeout=timeout)
            print(f"{GREEN}Successfully connected to {hostname} using password.{NC}")
            logging.info(f"SSH connection established to {hostname} using password")
            return
        except paramiko.AuthenticationException:
            print(f"{RED}Authentication failed. Please check your credentials.{NC}")
            logging.error(f"SSH authentication failed for {hostname}")
            sys.exit(1)
    elif auth_method == 'key':
        default_key_path = os.path.expanduser('~/.ssh/id_rsa')
        key_path = input(f"Enter the path to your SSH private key (default: {default_key_path}): ") or default_key_path
        key_path = os.path.expanduser(key_path)

        if not os.path.isfile(key_path):
            print(f"{RED}Error: The specified key file does not exist: {key_path}{NC}")
            logging.error(f"SSH key file not found: {key_path}")
            sys.exit(1)

        try:
            key = load_ssh_key(key_path)
            ssh_client.connect(hostname, username=username, pkey=key, timeout=timeout)
        except paramiko.ssh_exception.PasswordRequiredException:
            key_password = getpass.getpass("Enter passphrase for SSH key: ")
            try:
                key = load_ssh_key(key_path, key_password)
                ssh_client.connect(hostname, username=username, pkey=key, timeout=timeout)
            except paramiko.SSHException as ssh_ex:
                print(f"{RED}Unable to use the SSH key: {ssh_ex}{NC}")
                logging.error(f"SSH key authentication failed: {ssh_ex}")
                sys.exit(1)
        except paramiko.SSHException as ssh_ex:
            print(f"{RED}Unable to establish SSH connection: {ssh_ex}{NC}")
            logging.error(f"SSH connection failed: {ssh_ex}")
            sys.exit(1)

        print(f"{GREEN}Successfully connected to {hostname} using SSH key.{NC}")
        logging.info(f"SSH connection established to {hostname} using SSH key")
    else:
        print(f"{RED}Invalid authentication method. Please choose 'password' or 'key'.{NC}")
        sys.exit(1)


def close_ssh():
    global ssh_client
    if ssh_client:
        ssh_client.close()
        print(f"{GREEN}SSH connection closed.{NC}")
        logging.info("SSH connection closed")
        ssh_client = None


def main():
    print(f"{GREEN}Network Configuration Audit{NC}")
    logging.info("Starting network configuration audit")

    mode = input("Choose mode (local/remote): ").lower()
    remote = mode == "remote"

    if remote:
        try:
            hostname = validate_hostname(input("Enter the IP or hostname of the target server: "))
            connect_ssh(hostname, timeout=15)  # 15-second timeout, adjust as needed
        except ValueError as e:
            print(f"{RED}Error: {str(e)}{NC}")
            sys.exit(1)

    while True:
        print_menu()
        choice = input(f"{YELLOW}Enter your choice: {NC}")

        if choice == "1":
            list_interfaces(remote)
        elif choice == "2":
            show_ip_addresses(remote)
        elif choice == "3":
            show_routing_table(remote)
        elif choice == "4":
            show_firewall_rules(remote)
        elif choice == "5":
            list_open_connections(remote)
        elif choice == "6":
            list_docker_nets(remote)
        elif choice == "7":
            list_interfaces(remote)
            show_ip_addresses(remote)
            show_routing_table(remote)
            show_firewall_rules(remote)
            list_open_connections(remote)
            list_docker_nets(remote)
        elif choice == "8":
            if remote:
                close_ssh()
            print(f"{GREEN}Exiting. Thank you for using the Network Configuration Audit tool.{NC}")
            break
        else:
            print(f"{RED}Invalid choice. Please try again.{NC}")

    logging.info("Network configuration audit completed")


if __name__ == "__main__":
    main()
