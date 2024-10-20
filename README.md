# SSDP Relay Project

This project is a Python-based implementation of an SSDP (Simple Service Discovery Protocol) relay. It listens for incoming SSDP requests on a specified interface, forwards those requests to a multicast address, and relays any responses back to the original requester.

## Features
- **SSDP Request Handling**: Detects and relays `M-SEARCH` SSDP requests from clients.
- **Multicast SSDP Forwarding**: Forwards requests to the SSDP multicast address.
- **Response Relay**: Listens for responses from SSDP servers and forwards them back to the requesting client.
- **Configurable Interfaces**: Allows the configuration of different network interfaces for clients and services.

## Installation

1. Clone this repository to your local machine:

2. (Optional) Create a virtual environment for this project:

    - On **Windows**:
    
        ```bash
        python -m venv venv
        venv\Scripts\activate
        ```

    - On **macOS/Linux**:

        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```

3. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run the SSDP relay, use the following command:

```bash
python -m my_ssdp_project.main
```