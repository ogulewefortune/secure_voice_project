# Secure Voice Project

A secure voice communication system with end-to-end encryption.

## Features

- Real-time voice communication
- End-to-end encryption
- Secure key exchange
- Network protocol implementation

## Project Structure

```
├── src/              # Source code
├── tests/            # Test files
├── demo/             # Demo scripts and scenarios
├── docs/             # Documentation
├── requirements.txt  # Python dependencies
├── run_server.py    # Server launcher
├── run_client.py    # Client launcher
└── README.md        # This file
```

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start the voice server:
   ```bash
   python3 run_server.py
   ```

3. Start the web interface (in a new terminal):
   ```bash
   python3 run_web_server.py
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

5. Click "Connect to Server" and then "Record & Send" to start recording!

## Alternative: Command Line Client

If you prefer the command-line client:
```bash
python3 run_client.py
```

## Security Testing

Run comprehensive security tests to verify protection against attacks:

```bash
# Automated security tests
python3 tests/run_security_tests.py

# Interactive demonstration tests
python3 tests/security_test_manual.py
```

The test suite validates protection against:
- **Eavesdropping**: Unauthorized interception of encrypted messages
- **Imposter Clients**: Attackers trying to impersonate legitimate clients
- **Man-in-the-Middle**: Attackers intercepting and modifying messages

See [SECURITY_TESTS.md](SECURITY_TESTS.md) for detailed documentation.

## Documentation

- [Setup Guide](docs/setup_guide.md)
- [API Reference](docs/api_reference.md)
- [Security Tests](SECURITY_TESTS.md)
- [Technical Documentation](docs/technical_documentation.md)

## License

[Add your license here]

