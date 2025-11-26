# Intrusion Detection System

## Overview

The Secure Voice Communication system includes a comprehensive Intrusion Detection System (IDS) that automatically detects and alerts on security threats including eavesdropping attempts, imposter clients, man-in-the-middle attacks, and message tampering.

## Features

### Real-Time Threat Detection

The IDS monitors all network activity and detects:

1. **Eavesdropping Attacks**
   - Failed decryption attempts (wrong key)
   - GCM authentication tag failures
   - Unauthorized decryption attempts

2. **Imposter Client Attacks**
   - Failed key exchange attempts
   - Invalid public key submissions
   - Key derivation failures

3. **Man-in-the-Middle Attacks**
   - Message authentication failures
   - Modified ciphertext detection
   - GCM tag mismatches

4. **Message Tampering**
   - HMAC integrity check failures
   - Modified message detection
   - Integrity violations

5. **Suspicious Activity**
   - Rapid connection attempts
   - Brute force patterns
   - Reconnaissance activity

## How It Works

### Detection Mechanisms

#### 1. Decryption Failure Detection
When a decryption attempt fails (wrong key or corrupted data), the IDS:
- Logs the failure with source IP
- Tracks failure count per IP
- Generates HIGH severity alert on first failure
- Identifies as possible eavesdropping attack

#### 2. Key Exchange Failure Detection
When key exchange fails:
- Tracks failures per IP
- Generates MEDIUM severity alert after 2 failures
- Identifies as possible imposter client
- Prevents unauthorized access

#### 3. Integrity Violation Detection
When HMAC integrity check fails:
- Generates CRITICAL severity alert immediately
- Identifies as possible MITM or tampering
- Blocks corrupted data

#### 4. Authentication Failure Detection
When GCM authentication tag fails:
- Generates CRITICAL severity alert
- Identifies as possible MITM attack
- Prevents message replay/modification

#### 5. Suspicious Connection Pattern Detection
When rapid connections detected:
- Tracks connection attempts per IP
- Generates MEDIUM severity alert after 5 attempts
- Identifies as possible brute force attack

### Alert System

#### Alert Levels

- **LOW**: Minor suspicious activity
- **MEDIUM**: Moderate threat (multiple failures, suspicious patterns)
- **HIGH**: Significant threat (decryption failures, key issues)
- **CRITICAL**: Immediate threat (integrity violations, authentication failures)

#### Alert Components

Each alert includes:
- **Timestamp**: When the threat was detected
- **Threat Type**: Category of attack (EAVESDROPPING, IMPOSTER_CLIENT, etc.)
- **Level**: Severity (LOW, MEDIUM, HIGH, CRITICAL)
- **Message**: Human-readable description
- **Source IP**: Origin of the threat (if available)
- **Details**: Additional information about the threat

### Web Interface Integration

#### Real-Time Alerts
- Alerts appear instantly in the Security Alerts panel
- Color-coded by severity level
- Critical alerts pulse and animate
- Alert count badge shows total threats

#### Browser Notifications
- Critical alerts trigger browser notifications
- Requires user permission
- Provides immediate awareness

#### Alert History
- Last 50 alerts displayed
- Scrollable list
- Timestamp and details for each alert

## Usage

### Viewing Alerts

1. **Web Interface**
   - Open the Security Alerts panel (right side)
   - View real-time threat detection
   - See alert count badge

2. **Server Console**
   - Alerts logged to console
   - Format: `[TIMESTAMP] [ALERT] SECURITY ALERT: [details]`

3. **Programmatic Access**
   ```python
   from src.intrusion_detection import get_ids
   
   ids = get_ids()
   recent_alerts = ids.get_recent_alerts(limit=50)
   stats = ids.get_statistics()
   ```

### Alert Types

#### EAVESDROPPING
- **Trigger**: Failed decryption with wrong key
- **Level**: HIGH
- **Message**: "Failed decryption attempt detected from [IP]"
- **Details**: Failure count, error message

#### IMPOSTER_CLIENT
- **Trigger**: Multiple key exchange failures
- **Level**: MEDIUM
- **Message**: "Multiple key exchange failures from [IP]"
- **Details**: Failure count, reason

#### MAN_IN_THE_MIDDLE
- **Trigger**: GCM authentication tag failure
- **Level**: CRITICAL
- **Message**: "Authentication failure detected from [IP]"
- **Details**: Failure count, error message

#### INTEGRITY_VIOLATION
- **Trigger**: HMAC integrity check failure
- **Level**: CRITICAL
- **Message**: "Integrity check failed for data from [IP]"
- **Details**: Failure count, threat description

#### MESSAGE_TAMPERING
- **Trigger**: Message modification detected
- **Level**: CRITICAL
- **Message**: "Message tampering detected from [IP]"
- **Details**: Threat description

#### SUSPICIOUS_ACTIVITY
- **Trigger**: Rapid connection attempts
- **Level**: MEDIUM
- **Message**: "Suspicious connection pattern from [IP]"
- **Details**: Connection attempt count

## Configuration

### Thresholds

Default thresholds can be adjusted in `src/intrusion_detection.py`:

```python
self.DECRYPTION_FAILURE_THRESHOLD = 1  # Alert on first failure
self.KEY_EXCHANGE_FAILURE_THRESHOLD = 2  # Alert after 2 failures
self.INTEGRITY_FAILURE_THRESHOLD = 1  # Alert on first failure
self.CONNECTION_ATTEMPT_THRESHOLD = 5  # Alert after 5 rapid attempts
```

### Alert Callbacks

Register custom alert handlers:

```python
from src.intrusion_detection import get_ids

def my_alert_handler(alert):
    # Custom handling (email, SMS, etc.)
    send_email(alert.message)

ids = get_ids()
ids.register_alert_callback(my_alert_handler)
```

## Security Guarantees

### What Gets Detected

[OK] **Eavesdropping**: Attackers trying to decrypt without proper key  
[OK] **Imposter Clients**: Attackers trying to impersonate legitimate clients  
[OK] **MITM Attacks**: Attackers modifying or intercepting messages  
[OK] **Message Tampering**: Attackers modifying message content  
[OK] **Brute Force**: Rapid connection attempts  

### What Gets Protected

[OK] **Confidentiality**: Encryption prevents unauthorized reading  
[OK] **Authentication**: Key exchange prevents impersonation  
[OK] **Integrity**: HMAC and GCM tags detect tampering  
[OK] **Availability**: Connection pattern detection prevents DoS  

## Integration Points

### Server Integration (`src/server.py`)

- Detects decryption failures during audio processing
- Detects key exchange failures during connection
- Detects authentication failures (GCM tag mismatches)
- Tracks connection patterns

### Web Server Integration (`web_server.py`)

- Detects integrity violations (HMAC failures)
- Detects decryption failures
- Broadcasts alerts to all web clients
- Provides alert API endpoints

### Web Interface (`templates/index.html`)

- Displays real-time security alerts
- Shows alert count badge
- Provides browser notifications for critical alerts
- Maintains alert history

## Example Scenarios

### Scenario 1: Eavesdropping Attempt

1. Attacker intercepts encrypted message
2. Attacker tries to decrypt with wrong key
3. **IDS Detects**: Decryption failure
4. **Alert Generated**: HIGH severity EAVESDROPPING alert
5. **User Notified**: Alert appears in web interface

### Scenario 2: Imposter Client

1. Attacker tries to connect with stolen public key
2. Key exchange fails (no private key)
3. Attacker tries again
4. **IDS Detects**: Multiple key exchange failures
5. **Alert Generated**: MEDIUM severity IMPOSTER_CLIENT alert
6. **User Notified**: Alert appears in web interface

### Scenario 3: Man-in-the-Middle Attack

1. Attacker intercepts and modifies message
2. GCM authentication tag doesn't match
3. **IDS Detects**: Authentication failure
4. **Alert Generated**: CRITICAL severity MAN_IN_THE_MIDDLE alert
5. **User Notified**: Critical alert with browser notification

### Scenario 4: Message Tampering

1. Attacker modifies audio data
2. HMAC integrity check fails
3. **IDS Detects**: Integrity violation
4. **Alert Generated**: CRITICAL severity INTEGRITY_VIOLATION alert
5. **User Notified**: Critical alert with browser notification

## Statistics

The IDS provides statistics:

```python
stats = ids.get_statistics()
# Returns:
# {
#     'total_alerts': 15,
#     'failed_decryption_attempts': {'192.168.1.100': 3},
#     'failed_key_exchanges': {'192.168.1.101': 2},
#     'failed_integrity_checks': {},
#     'failed_authentications': {'192.168.1.100': 1},
#     'connection_attempts': {'192.168.1.102': 6},
#     'recent_alerts': 5
# }
```

## Best Practices

1. **Monitor Alerts Regularly**: Check the Security Alerts panel frequently
2. **Investigate Critical Alerts**: Immediately investigate CRITICAL severity alerts
3. **Review Patterns**: Look for repeated attacks from same IP
4. **Adjust Thresholds**: Tune thresholds based on your environment
5. **Log Alerts**: Consider logging alerts to external system
6. **Set Up Notifications**: Enable browser notifications for critical alerts

## Troubleshooting

### Alerts Not Appearing

- Check browser console for errors
- Verify SocketIO connection is established
- Check server logs for IDS activity

### Too Many Alerts

- Adjust thresholds in `intrusion_detection.py`
- Review legitimate connection patterns
- Consider IP whitelisting for known clients

### Missing Alerts

- Verify IDS is initialized in server/web_server
- Check alert callbacks are registered
- Review detection thresholds

---

**Last Updated**: 2024  
**Status**: Active Monitoring  
**Coverage**: Eavesdropping, Imposter Clients, MITM, Tampering, Suspicious Activity

