# Wifi2Go // Open Hotspot Bypass Tool

**Wifi2Go** is a Python script that empowers you to change the MAC address of a network interface on a macOS system and perform an auto bypass to connect to a specific WiFi network automatically. This script utilizes the `scapy` library for capturing network traffic and `subprocess` for executing system commands.

## Prerequisites

Before using **Wifi2Go**, ensure you meet the following prerequisites:

1. **macOS:** This script is tailored for macOS.

2. **Python:** Python 3 must be installed on your system.

3. **Required Python Libraries:** Install the necessary Python libraries using the following command:

   ```bash
   pip install scapy argparse
   ```

## Usage

### Changing MAC Address

To change the MAC address of a network interface using **Wifi2Go**, execute the script with the `-i` or `--interface` option followed by the name of the interface you wish to modify. For example:

```bash
sudo python Wifi2Go.py -i en0
```

Replace `en0` with your network interface's name. The script will prompt you to specify the new MAC address and then proceed to change it.

### WiFi Auto Bypass

The WiFi auto bypass feature in **Wifi2Go** allows you to automatically connect to a specific WiFi network. Here's how to use it:

1. Run the script with the `-i` or `--interface` option, followed by your network interface's name. For instance:

   ```bash
   sudo python Wifi2Go.py -i en0
   ```

   Make sure to replace `en0` with your actual network interface.

2. The script will display a list of available WiFi networks. Enter the SSID (network name) of the network you want to scan for clients.

3. **Wifi2Go** will capture network traffic and identify clients connected to the specified WiFi network.

4. It will select the client with the highest count of packets and change your network interface's MAC address to match that client's MAC address.

5. Finally, the script will connect your system to the specified WiFi network.

## Important Notes

- Always run the script with administrative privileges (using `sudo`) because changing the MAC address and capturing network traffic require elevated permissions.

- Use this script responsibly, as it involves manipulating network interfaces and network traffic. Ensure compliance with local regulations and policies.

- The script has been tailored for macOS and may not function on other operating systems.

- The provided MAC address must be in the correct format (e.g., `00:11:22:33:44:55`).

- The auto bypass feature allows you to connect to a specific WiFi network automatically. Ensure you have the necessary permissions to access the network you intend to connect to.
