# Herramienta de Auditoría de Configuración de Red (ESP)

## Visión General

Esta Herramienta de Auditoría de Configuración de Red es un script Python diseñado para auditar y reportar configuraciones de red en sistemas Linux, tanto localmente como de forma remota. Proporciona una visión completa de las interfaces de red activas, direcciones IP, tablas de enrutamiento, reglas de cortafuegos (UFW), conexiones de red abiertas y redes de Docker. Esta herramienta es particularmente útil para administradores de sistemas y profesionales de redes que necesitan comprobar rápidamente varios aspectos de su configuración de red en sistemas locales o remotos.

## Características

- **Auditoría Local y Remota**: Capacidad de auditar sistemas locales y remotos mediante SSH.
- **Interfaces de red**: Lista todas las interfaces de red y su estado (activo/inactivo).
- **Direcciones IP**: Muestra las direcciones IP asignadas a cada interfaz de red.
- **Tabla de Enrutamiento**: Muestra la tabla de enrutamiento actual.
- **Reglas del cortafuegos**: Muestra las primeras reglas del cortafuegos (UFW).
- **Conexiones abiertas**: Lista algunas de las conexiones de red abiertas.
- **Redes de Docker**: Muestra las redes de Docker, incluyendo nombres de host y direcciones IP.
- **Menú Interactivo**: Proporciona un menú interactivo para facilitar la navegación y la selección de comprobaciones específicas.
- **Salida codificada por colores**: Mejora la legibilidad resaltando la información importante.
- **Registro**: Registra todas las acciones y errores en `audit_network.log` con fines de auditoría y depuración.
- **Verificación de clave de host SSH**: Implementa verificación de clave de host para conexiones SSH remotas.

## Requisitos previos

- **Python 3.x**: Asegúrate de que Python 3.x está instalado en tu sistema.
- **Librerías Python**: El script instalará automáticamente las siguientes librerías si no están presentes:
  - `tabulate`: Para formatear tablas en la salida.
  - `paramiko`: Para conexiones SSH a sistemas remotos.
- **Comandos del sistema**: El script requiere que los siguientes comandos estén disponibles en el sistema auditado:
  - `ip`
  - `ss`
  - `ufw` (para reglas de cortafuegos)
  - `docker` (para información de redes de Docker)

## Instalación

1. Clona el repositorio en tu máquina local:

```bash
git clone https://github.com/elliotsecops/network-auditor.git
cd network-auditor
```

2. El script instalará automáticamente las dependencias necesarias al ejecutarse.

## Uso

1. Ejecute el script:

```bash
python network_audit.py
```

2. Elija el modo de auditoría (local o remoto).
3. Si se selecciona el modo remoto, proporcione la información de conexión SSH cuando se le solicite.
4. El script presentará un menú interactivo. Elija la opción deseada para realizar comprobaciones específicas o ejecutar todas las comprobaciones secuencialmente.

### Opciones de Autenticación SSH (para auditoría remota)

- **Agente SSH**: El script intentará primero usar el agente SSH si está disponible.
- **Contraseña**: Puede introducir la contraseña SSH cuando se le solicite.
- **Clave SSH**: Puede especificar la ruta a su clave privada SSH.

### Ejemplo del output:

```
Network Configuration Audit

Choose mode (local/remote): remote
Enter the IP or hostname of the target server: 192.168.1.100
Enter SSH username: user
Successfully connected to 192.168.1.100 using SSH agent.

Network Configuration Audit Menu:
1. List network interfaces
2. Show IP addresses
3. Show routing table
4. Show firewall rules
5. List open network connections
6. List Docker networks
7. Run all checks
8. Exit

Enter your choice: 7

Network interfaces and their status:
+--------------+--------+
| Interface    | Status |
+--------------+--------+
| lo           | UP     |
| eth0         | UP     |
| wlan0        | DOWN   |
+--------------+--------+

IP addresses assigned to each interface:
+--------------+----------------+
| Interface    | IP Address     |
+--------------+----------------+
| lo           | 127.0.0.1/8    |
| eth0         | 192.168.1.100/24 |
+--------------+----------------+

Current routing table:
+------------------------------------------------------------------------+
| Route                                                                  |
+------------------------------------------------------------------------+
| default via 192.168.1.1 dev eth0                                       |
| 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100      |
| 127.0.0.0/8 dev lo proto kernel scope link src 127.0.0.1               |
+------------------------------------------------------------------------+

Firewall (UFW) rules:
+----------------------------------------+
| UFW Rule                               |
+----------------------------------------+
| [ 1] 22/tcp ALLOW IN Anywhere          |
| [ 2] 80/tcp ALLOW IN Anywhere          |
+----------------------------------------+

Some open network connections:
+--------+-------------------+-------------------+
| State  | Local Address     | Remote Address    |
+--------+-------------------+-------------------+
| LISTEN | 0.0.0.0:22        | 0.0.0.0:*         |
| LISTEN | 0.0.0.0:80        | 0.0.0.0:*         |
+--------+-------------------+-------------------+

Docker Networks:
+----------------+------------+----------------+
| Network Name   | Host Name  | Host IP        |
+----------------+------------+----------------+
| bridge         |            |                |
|                | alpine1    | 172.17.0.2/16  |
|                | alpine2    | 172.17.0.3/16  |
+----------------+------------+----------------+
| host           |            |                |
+----------------+------------+----------------+
| none           |            |                |
+----------------+------------+----------------+

Enter your choice: 8
SSH connection closed.
Exiting. Thank you for using the Network Configuration Audit tool.
```

## Logging

Todas las acciones y errores se registran en `audit_network.log`. Este archivo de registro puede ser útil para propósitos de auditoría y depuración.

## Seguridad

El script ahora incluye verificación de clave de host SSH para conexiones remotas, mejorando la seguridad al prevenir ataques de tipo "man-in-the-middle".

## Contribuciones

¡Las contribuciones son bienvenidas! Si tienes alguna sugerencia, informe de errores o petición de características, por favor abre una issue o envía un pull request.

---

# Network Configuration Audit Tool

## Overview

The Network Configuration Audit Tool is a Python script designed to audit and report system network configurations on Linux systems, both locally and remotely. It provides a comprehensive overview of active network interfaces, IP addresses, routing tables, firewall rules (UFW), open network connections, and Docker networks. The tool is particularly useful for system administrators and network professionals who need to quickly check various aspects of their network setup on local or remote systems.

## Features

- **Local and Remote Auditing**: Ability to audit both local and remote systems via SSH.
- **Network Interfaces**: Lists all network interfaces and their status (active/inactive).
- **IP Addresses**: Displays the IP addresses assigned to each network interface.
- **Routing Table**: Shows the current routing table.
- **Firewall Rules**: Displays the firewall rules (UFW).
- **Open Connections**: Lists some of the open network connections.
- **Docker Networks**: Shows Docker networks, including host names and IP addresses.
- **Interactive Menu**: Provides an interactive menu for easy navigation and selection of specific checks.
- **Color-Coded Output**: Enhances readability by highlighting important information.
- **Logging**: Logs all actions and errors to `audit_network.log` for auditing and debugging purposes.
- **SSH Host Key Verification**: Implements host key verification for remote SSH connections.

## Prerequisites

- **Python 3.x**: Ensure Python 3.x is installed on your system.
- **Python Libraries**: The script will automatically install the following libraries if not present:
  - `tabulate`: For formatting tables in the output.
  - `paramiko`: For SSH connections to remote systems.
- **System Commands**: The script requires the following commands to be available on the audited system:
  - `ip`
  - `ss`
  - `ufw` (for firewall rules)
  - `docker` (for Docker network information)

## Installation

1. Clone the repository to your local machine:

```bash
git clone https://github.com/elliotsecops/network-auditor.git
cd network-auditor
```

2. The script will automatically install the necessary dependencies when run.

## Usage

1. Run the script:

```bash
python network_audit.py
```

2. Choose the auditing mode (local or remote).
3. If remote mode is selected, provide SSH connection information when prompted.
4. The script will present an interactive menu. Choose the desired option to perform specific checks or run all checks sequentially.

### SSH Authentication Options (for remote auditing)

- **SSH Agent**: The script will first attempt to use the SSH agent if available.
- **Password**: You can enter the SSH password when prompted.
- **SSH Key**: You can specify the path to your SSH private key.

### Example Output:

```
Network Configuration Audit

Choose mode (local/remote): remote
Enter the IP or hostname of the target server: 192.168.1.100
Enter SSH username: user
Successfully connected to 192.168.1.100 using SSH agent.

Network Configuration Audit Menu:
1. List network interfaces
2. Show IP addresses
3. Show routing table
4. Show firewall rules
5. List open network connections
6. List Docker networks
7. Run all checks
8. Exit

Enter your choice: 7

Network interfaces and their status:
+--------------+--------+
| Interface    | Status |
+--------------+--------+
| lo           | UP     |
| eth0         | UP     |
| wlan0        | DOWN   |
+--------------+--------+

IP addresses assigned to each interface:
+--------------+----------------+
| Interface    | IP Address     |
+--------------+----------------+
| lo           | 127.0.0.1/8    |
| eth0         | 192.168.1.100/24 |
+--------------+----------------+

Current routing table:
+------------------------------------------------------------------------+
| Route                                                                  |
+------------------------------------------------------------------------+
| default via 192.168.1.1 dev eth0                                       |
| 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100      |
| 127.0.0.0/8 dev lo proto kernel scope link src 127.0.0.1               |
+------------------------------------------------------------------------+

Firewall (UFW) rules:
+----------------------------------------+
| UFW Rule                               |
+----------------------------------------+
| [ 1] 22/tcp ALLOW IN Anywhere          |
| [ 2] 80/tcp ALLOW IN Anywhere          |
+----------------------------------------+

Some open network connections:
+--------+-------------------+-------------------+
| State  | Local Address     | Remote Address    |
+--------+-------------------+-------------------+
| LISTEN | 0.0.0.0:22        | 0.0.0.0:*         |
| LISTEN | 0.0.0.0:80        | 0.0.0.0:*         |
+--------+-------------------+-------------------+

Docker Networks:
+----------------+------------+----------------+
| Network Name   | Host Name  | Host IP        |
+----------------+------------+----------------+
| bridge         |            |                |
|                | alpine1    | 172.17.0.2/16  |
|                | alpine2    | 172.17.0.3/16  |
+----------------+------------+----------------+
| host           |            |                |
+----------------+------------+----------------+
| none           |            |                |
+----------------+------------+----------------+

Enter your choice: 8
SSH connection closed.
Exiting. Thank you for using the Network Configuration Audit tool.
```

## Logging

All actions and errors are logged to `audit_network.log`. This log file can be useful for auditing and debugging purposes.

## Security

The script now includes SSH host key verification for remote connections, enhancing security by preventing man-in-the-middle attacks.

## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.