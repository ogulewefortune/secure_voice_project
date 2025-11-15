# Setup Guide

## Prerequisites
- Python 3.8 or higher
- pip package manager

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure settings in `src/config.py` if needed

## Running the Application

### Start the Server
```bash
python run_server.py
```

### Start the Client
```bash
python run_client.py
```

## Troubleshooting

### Common Issues
- Port already in use: Change the port in `config.py`
- Audio device not found: Check audio device permissions
- Connection refused: Ensure server is running before starting client

