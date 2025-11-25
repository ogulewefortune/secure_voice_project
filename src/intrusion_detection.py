"""
Intrusion Detection System
Detects and alerts on security threats: eavesdropping, imposter clients, MITM attacks.
"""

import json
import threading
from datetime import datetime
from collections import defaultdict
from enum import Enum


class ThreatType(Enum):
    """Types of security threats."""
    EAVESDROPPING = "EAVESDROPPING"
    IMPOSTER_CLIENT = "IMPOSTER_CLIENT"
    MAN_IN_THE_MIDDLE = "MAN_IN_THE_MIDDLE"
    MESSAGE_TAMPERING = "MESSAGE_TAMPERING"
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"


class AlertLevel(Enum):
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityAlert:
    """Represents a security alert."""
    
    def __init__(self, threat_type, level, message, source_ip=None, details=None):
        self.timestamp = datetime.now()
        self.threat_type = threat_type
        self.level = level
        self.message = message
        self.source_ip = source_ip
        self.details = details or {}
    
    def to_dict(self):
        """Convert alert to dictionary."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'threat_type': self.threat_type.value,
            'level': self.level.value,
            'message': self.message,
            'source_ip': self.source_ip,
            'details': self.details
        }
    
    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S')}] [{self.level.value}] {self.threat_type.value}: {self.message}"


class IntrusionDetectionSystem:
    """Intrusion Detection System for monitoring security threats."""
    
    def __init__(self, alert_callback=None):
        self.alerts = []
        self.alert_callbacks = []
        if alert_callback:
            self.alert_callbacks.append(alert_callback)
        
        # Track suspicious activities per IP
        self.failed_decryption_attempts = defaultdict(int)
        self.failed_key_exchanges = defaultdict(int)
        self.failed_integrity_checks = defaultdict(int)
        self.failed_authentications = defaultdict(int)
        self.connection_attempts = defaultdict(int)
        
        # Thresholds for alerts
        self.DECRYPTION_FAILURE_THRESHOLD = 1  # Alert on first failure
        self.KEY_EXCHANGE_FAILURE_THRESHOLD = 2  # Alert after 2 failures
        self.INTEGRITY_FAILURE_THRESHOLD = 1  # Alert on first failure
        self.CONNECTION_ATTEMPT_THRESHOLD = 5  # Alert after 5 rapid attempts
        
        self.lock = threading.Lock()
    
    def register_alert_callback(self, callback):
        """Register a callback function to be called when alerts are generated."""
        self.alert_callbacks.append(callback)
    
    def _emit_alert(self, alert):
        """Emit alert to all registered callbacks."""
        with self.lock:
            self.alerts.append(alert)
            # Keep only last 1000 alerts
            if len(self.alerts) > 1000:
                self.alerts = self.alerts[-1000:]
        
        # Call all registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Error in alert callback: {e}")
    
    def detect_decryption_failure(self, source_ip, error_message):
        """
        Detect failed decryption attempt (possible eavesdropping).
        
        Args:
            source_ip: IP address of the source
            error_message: Error message from decryption failure
        """
        self.failed_decryption_attempts[source_ip] += 1
        count = self.failed_decryption_attempts[source_ip]
        
        if count >= self.DECRYPTION_FAILURE_THRESHOLD:
            alert = SecurityAlert(
                threat_type=ThreatType.EAVESDROPPING,
                level=AlertLevel.HIGH,
                message=f"Failed decryption attempt detected from {source_ip}",
                source_ip=source_ip,
                details={
                    'failure_count': count,
                    'error': str(error_message)[:200],
                    'threat': 'Possible eavesdropping attack - attacker trying to decrypt without proper key',
                    'attack_description': 'Attacker intercepted encrypted message and attempted decryption with wrong key',
                    'what_attacker_tried': 'Decrypt encrypted audio data without proper AES-256-GCM key',
                    'protection': 'AES-256-GCM encryption prevents decryption without correct key'
                }
            )
            self._emit_alert(alert)
            return True
        return False
    
    def detect_key_exchange_failure(self, source_ip, reason):
        """
        Detect failed key exchange (possible imposter client).
        
        Args:
            source_ip: IP address of the source
            reason: Reason for key exchange failure
        """
        self.failed_key_exchanges[source_ip] += 1
        count = self.failed_key_exchanges[source_ip]
        
        if count >= self.KEY_EXCHANGE_FAILURE_THRESHOLD:
            alert = SecurityAlert(
                threat_type=ThreatType.IMPOSTER_CLIENT,
                level=AlertLevel.MEDIUM,
                message=f"Multiple key exchange failures from {source_ip}",
                source_ip=source_ip,
                details={
                    'failure_count': count,
                    'reason': reason,
                    'threat': 'Possible imposter client - attacker cannot complete key exchange',
                    'attack_description': 'Attacker attempted to impersonate legitimate client',
                    'what_attacker_tried': f'Connect to server with invalid key exchange: {reason}',
                    'protection': 'ECDH key exchange requires private key from both parties'
                }
            )
            self._emit_alert(alert)
            return True
        return False
    
    def detect_integrity_violation(self, source_ip, details=None):
        """
        Detect HMAC integrity check failure (possible MITM or tampering).
        
        Args:
            source_ip: IP address of the source
            details: Additional details about the violation
        """
        self.failed_integrity_checks[source_ip] += 1
        count = self.failed_integrity_checks[source_ip]
        
        if count >= self.INTEGRITY_FAILURE_THRESHOLD:
            alert = SecurityAlert(
                threat_type=ThreatType.INTEGRITY_VIOLATION,
                level=AlertLevel.CRITICAL,
                message=f"Integrity check failed for data from {source_ip}",
                source_ip=source_ip,
                details={
                    'failure_count': count,
                    'threat': 'Possible man-in-the-middle attack or message tampering',
                    'attack_description': 'Message integrity check failed - data may have been modified',
                    'what_attacker_tried': 'Modify audio data or send corrupted message',
                    'protection': 'HMAC-SHA256 integrity check detects any modification',
                    **(details or {})
                }
            )
            self._emit_alert(alert)
            return True
        return False
    
    def detect_authentication_failure(self, source_ip, error_message):
        """
        Detect GCM authentication tag failure (possible MITM).
        
        Args:
            source_ip: IP address of the source
            error_message: Error message from authentication failure
        """
        self.failed_authentications[source_ip] += 1
        count = self.failed_authentications[source_ip]
        
        if count >= self.DECRYPTION_FAILURE_THRESHOLD:
            alert = SecurityAlert(
                threat_type=ThreatType.MAN_IN_THE_MIDDLE,
                level=AlertLevel.CRITICAL,
                message=f"Authentication failure detected from {source_ip}",
                source_ip=source_ip,
                details={
                    'failure_count': count,
                    'error': str(error_message)[:200],
                    'threat': 'Possible man-in-the-middle attack - message authentication tag invalid',
                    'attack_description': 'Encrypted message authentication failed - message may have been modified',
                    'what_attacker_tried': 'Modify encrypted message or intercept and tamper with ciphertext',
                    'protection': 'AES-256-GCM authentication tag prevents undetected tampering'
                }
            )
            self._emit_alert(alert)
            return True
        return False
    
    def detect_suspicious_connection_pattern(self, source_ip):
        """
        Detect suspicious connection pattern (rapid connection attempts).
        
        Args:
            source_ip: IP address of the source
        """
        self.connection_attempts[source_ip] += 1
        count = self.connection_attempts[source_ip]
        
        if count >= self.CONNECTION_ATTEMPT_THRESHOLD:
            alert = SecurityAlert(
                threat_type=ThreatType.SUSPICIOUS_ACTIVITY,
                level=AlertLevel.MEDIUM,
                message=f"Suspicious connection pattern from {source_ip}",
                source_ip=source_ip,
                details={
                    'connection_attempts': count,
                    'threat': 'Possible brute force or reconnaissance attack'
                }
            )
            self._emit_alert(alert)
            return True
        return False
    
    def detect_message_tampering(self, source_ip, details=None):
        """
        Detect message tampering (modification detected).
        
        Args:
            source_ip: IP address of the source
            details: Additional details about the tampering
        """
        alert = SecurityAlert(
            threat_type=ThreatType.MESSAGE_TAMPERING,
            level=AlertLevel.CRITICAL,
            message=f"Message tampering detected from {source_ip}",
            source_ip=source_ip,
                details={
                    'threat': 'Message has been modified - possible man-in-the-middle attack',
                    'attack_description': 'Message tampering detected - data was modified in transit',
                    'what_attacker_tried': 'Modify message content during transmission',
                    'protection': 'HMAC and GCM authentication tags detect tampering',
                    **(details or {})
                }
        )
        self._emit_alert(alert)
        return True
    
    def get_recent_alerts(self, limit=50):
        """Get recent security alerts."""
        with self.lock:
            return self.alerts[-limit:]
    
    def get_alerts_by_type(self, threat_type):
        """Get alerts filtered by threat type."""
        with self.lock:
            return [alert for alert in self.alerts if alert.threat_type == threat_type]
    
    def get_alerts_by_level(self, level):
        """Get alerts filtered by alert level."""
        with self.lock:
            return [alert for alert in self.alerts if alert.level == level]
    
    def reset_ip_counters(self, source_ip):
        """Reset counters for a specific IP (after successful authentication)."""
        with self.lock:
            self.failed_decryption_attempts[source_ip] = 0
            self.failed_key_exchanges[source_ip] = 0
            self.failed_integrity_checks[source_ip] = 0
            self.failed_authentications[source_ip] = 0
    
    def get_statistics(self):
        """Get detection statistics."""
        with self.lock:
            return {
                'total_alerts': len(self.alerts),
                'failed_decryption_attempts': dict(self.failed_decryption_attempts),
                'failed_key_exchanges': dict(self.failed_key_exchanges),
                'failed_integrity_checks': dict(self.failed_integrity_checks),
                'failed_authentications': dict(self.failed_authentications),
                'connection_attempts': dict(self.connection_attempts),
                'recent_alerts': len([a for a in self.alerts if (datetime.now() - a.timestamp).seconds < 300])
            }


# Global IDS instance
_global_ids = None
_ids_lock = threading.Lock()


def get_ids():
    """Get or create global IDS instance."""
    global _global_ids
    with _ids_lock:
        if _global_ids is None:
            _global_ids = IntrusionDetectionSystem()
        return _global_ids

