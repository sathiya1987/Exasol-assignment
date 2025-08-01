# Exasol-assignment

This project implements an asyncio-based SSL client for interacting with a custom challenge-response server using a `.pem` certificate.

## Features

- Asynchronous communication using `asyncio`
- SSL/TLS connection with client certificate authentication
- SHA1 hashing for authentication tokens
- Input handled asynchronously to avoid blocking the event loop

## Requirements

- Python 3.7+
- A `.pem` file containing your certificate and private key

## Installation

```bash
# Clone repository or download script
git clone https://github.com/sathiya1987/Exasol-assignment.git
cd Exasol-assignment

# (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install any required dependencies (if needed)
pip install -r requirements.txt

```

## Usage

```bash
python3 clientlogic.py -c <path_to_pem_file> -H <hostname> -p <port>

#Command-line Arguments
-c	--certPath	Path to the PEM file	
-H	--host	Server hostname or IP address	
-p	--port	Port number to connect 

```

### Example

```bash
python3 clientlogic.py -c myclientcert.pem -H srv.exatest.dynu.net -p 3336

```

