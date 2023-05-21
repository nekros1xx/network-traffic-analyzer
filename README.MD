# Network Traffic Analyzer Documentation

## Introduction
The Network Traffic Analyzer is a Python program that captures network packets from a specified network interface and analyzes the traffic by extracting key information such as source and destination MAC addresses, and protocols used. It provides a basic level of network traffic monitoring and analysis.

## Usage
1. Ensure that Python is installed on your system.
2. Install the required dependencies listed in the `requirements.txt` file using the following command: `pip install -r requirements.txt`
3. Run the program using a Python interpreter.
4. Follow the prompts to enter the network interface and the number of packets to capture.
5. The program will capture the specified number of packets from the specified interface and display the extracted information for each packet on the screen.

## Requirements
- Python 3.x
- `pcapy` library (install using `pip install pcapy`)

## Functionality
1. User Input:
   - The program prompts the user to enter the network interface from which to capture traffic.
   - The user is also asked to provide the number of packets to capture.

2. Traffic Capture:
   - The program uses the `pcapy` library to capture network packets from the specified interface.
   - It captures the specified number of packets in a promiscuous mode.

3. Packet Analysis:
   - For each captured packet, the program extracts key information including:
     - Source MAC address
     - Destination MAC address
     - Protocol used

4. Display:
   - The program displays the extracted information for each packet on the screen.

## Example Usage
Enter the network interface to capture traffic from: eth0
Enter the number of packets to capture: 10

Capturing network traffic on interface eth0...

Packet #1
Source MAC: aa:bb:cc:dd:ee:ff
Destination MAC: ff:ee:dd:cc:bb:aa
Protocol: 2048

Packet #2
Source MAC: aa:bb:cc:dd:ee:ff
Destination MAC: ff:ee:dd:cc:bb:aa
Protocol: 2054

...

Packet #10
Source MAC: aa:bb:cc:dd:ee:ff
Destination MAC: ff:ee:dd:cc:bb:aa
Protocol: 2048

## Notes
- Capturing network traffic may require administrative privileges or appropriate permissions on some systems.
- The program captures packets in a promiscuous mode, allowing it to capture all network traffic on the specified interface.

---

Please note that this documentation serves as a guide for using the "Network Traffic Analyzer" program and can be customized or expanded upon based on your specific needs.

