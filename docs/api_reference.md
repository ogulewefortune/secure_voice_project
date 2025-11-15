# API Reference

## Audio Processor

### `capture_audio()`
Captures audio from the default microphone.

### `play_audio(audio_data)`
Plays audio data through the default speaker.

### `encode_audio(audio_data)`
Encodes audio data for network transmission.

### `decode_audio(encoded_data)`
Decodes audio data received from the network.

## Crypto Utils

### `generate_key_pair()`
Generates a public/private key pair for encryption.

### `encrypt_data(data, key)`
Encrypts data using the provided key.

### `decrypt_data(encrypted_data, key)`
Decrypts data using the provided key.

### `exchange_keys()`
Performs secure key exchange between client and server.

## Network Protocol

### `establish_connection(host, port)`
Establishes a network connection to the specified host and port.

### `send_message(socket, message)`
Sends a message over the network socket.

### `receive_message(socket)`
Receives a message from the network socket.

### `close_connection(socket)`
Closes the network connection.

