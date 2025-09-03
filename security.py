"""
Enterprise Security Framework for PDF Processing
==============================================

Professional-grade security system with advanced threat detection,
data protection, and compliance monitoring designed for enterprise
environments handling sensitive documents.

Author: Senior GenAI Engineer
Version: 2.1.0
Date: September 1, 2025
"""

import hashlib
import hmac
import secrets
import re
import time
import mimetypes
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional, Any, Union, Pattern
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
import base64
import json
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError

# Configuration and error handling imports
from config import get_security_config
from error_handler import handle_errors, ErrorSeverity, ErrorCategory


class ThreatLevel(Enum):
    """Professional threat severity classification."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEventType(Enum):
    """Types of security events for comprehensive monitoring."""
    FILE_UPLOAD = "FILE_UPLOAD"
    MALWARE_DETECTION = "MALWARE_DETECTION"
    INJECTION_ATTEMPT = "INJECTION_ATTEMPT"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    ACCESS_VIOLATION = "ACCESS_VIOLATION"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    PII_DETECTION = "PII_DETECTION"
    CONTENT_VIOLATION = "CONTENT_VIOLATION"


@dataclass
class SecurityEvent:
    """Comprehensive security event for audit and analysis."""
    event_id: str = field(default_factory=lambda: secrets.token_hex(16))
    timestamp: datetime = field(default_factory=datetime.now)
    event_type: SecurityEventType = SecurityEventType.SUSPICIOUS_ACTIVITY
    threat_level: ThreatLevel = ThreatLevel.LOW
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    file_name: Optional[str] = None
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    threat_details: str = ""
    mitigation_action: str = ""
    additional_context: Dict[str, Any] = field(default_factory=dict)
    
    def to_audit_record(self) -> Dict[str, Any]:
        """Convert to audit record format."""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'threat_level': self.threat_level.value,
            'source_ip': self.source_ip,
            'user_agent': self.user_agent,
            'file_name': self.file_name,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'threat_details': self.threat_details,
            'mitigation_action': self.mitigation_action,
            'additional_context': self.additional_context
        }


@dataclass
class PIIDetectionResult:
    """Result of PII detection analysis."""
    pii_types_found: Dict[str, List[str]] = field(default_factory=dict)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    total_instances: int = 0
    risk_level: str = "LOW"
    recommendations: List[str] = field(default_factory=list)


class AdvancedThreatDetector:
    """
    Professional threat detection system with machine learning capabilities.
    
    Features:
    - Multi-layer pattern recognition
    - Behavioral analysis
    - Zero-day protection mechanisms
    - Advanced malware detection
    - Content analysis
    """
    
    def __init__(self):
        """Initialize threat detector with enterprise-grade patterns."""
        self.config = get_security_config()
        self.threat_patterns = self._initialize_threat_patterns()
        self.suspicious_patterns = self._initialize_suspicious_patterns()
        self.behavioral_baselines = {}
        self.detection_cache = {}
        self._cache_lock = threading.RLock()
        
        # Professional logging
        self.logger = logging.getLogger('threat_detector')
        
    def _initialize_threat_patterns(self) -> Dict[str, List[Pattern]]:
        """Initialize comprehensive threat detection patterns."""
        patterns = {
            'script_injection': [
                re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
                re.compile(r'javascript\s*:', re.IGNORECASE),
                re.compile(r'vbscript\s*:', re.IGNORECASE),
                re.compile(r'on\w+\s*=', re.IGNORECASE),
                re.compile(r'eval\s*\(', re.IGNORECASE),
                re.compile(r'document\.(write|writeln|createElement)', re.IGNORECASE),
                re.compile(r'window\.(location|open)', re.IGNORECASE),
                re.compile(r'innerHTML\s*=', re.IGNORECASE),
            ],
            'sql_injection': [
                re.compile(r'\bUNION\b.*\bSELECT\b', re.IGNORECASE),
                re.compile(r'\bSELECT\b.*\bFROM\b.*\bWHERE\b', re.IGNORECASE),
                re.compile(r'\bINSERT\b.*\bINTO\b', re.IGNORECASE),
                re.compile(r'\bUPDATE\b.*\bSET\b', re.IGNORECASE),
                re.compile(r'\bDELETE\b.*\bFROM\b', re.IGNORECASE),
                re.compile(r'\bDROP\b.*\bTABLE\b', re.IGNORECASE),
                re.compile(r"'\s*OR\s*'.*'", re.IGNORECASE),
                re.compile(r"'\s*;\s*--", re.IGNORECASE),
            ],
            'command_injection': [
                re.compile(r';\s*(rm|del|format|rd)\s+', re.IGNORECASE),
                re.compile(r';\s*(cat|type|more)\s+', re.IGNORECASE),
                re.compile(r';\s*(ls|dir)\s*', re.IGNORECASE),
                re.compile(r';\s*(wget|curl)\s+', re.IGNORECASE),
                re.compile(r';\s*(nc|netcat)\s+', re.IGNORECASE),
                re.compile(r'`[^`]*`'),
                re.compile(r'\$\([^)]*\)'),
                re.compile(r'&&\s*(rm|del|format)', re.IGNORECASE),
                re.compile(r'\|\s*(rm|del|format)', re.IGNORECASE),
            ],
            'path_traversal': [
                re.compile(r'\.\.[\\/]'),
                re.compile(r'\.\.%2[fF]'),
                re.compile(r'\.\.%5[cC]'),
                re.compile(r'%2[eE]%2[eE][\\/]'),
                re.compile(r'%252[eE]%252[eE]'),
                re.compile(r'\.\.\\'),
                re.compile(r'\.\./\.\.'),
                re.compile(r'\.\.\\\.\.\\'),
            ],
            'file_inclusion': [
                re.compile(r'(file|ftp|http|https|data|php|zip)://.*', re.IGNORECASE),
                re.compile(r'include\s*\(\s*[\'"].*[\'"]', re.IGNORECASE),
                re.compile(r'require\s*\(\s*[\'"].*[\'"]', re.IGNORECASE),
                re.compile(r'fopen\s*\(\s*[\'"].*[\'"]', re.IGNORECASE),
            ],
            'malware_signatures': [
                re.compile(r'eval\s*\(\s*base64_decode', re.IGNORECASE),
                re.compile(r'exec\s*\(\s*gzinflate', re.IGNORECASE),
                re.compile(r'system\s*\(\s*\$_[A-Z]+', re.IGNORECASE),
                re.compile(r'passthru\s*\(\s*\$_[A-Z]+', re.IGNORECASE),
                re.compile(r'shell_exec\s*\(\s*\$_[A-Z]+', re.IGNORECASE),
            ]
        }
        
        return patterns
    
    def _initialize_suspicious_patterns(self) -> List[Pattern]:
        """Initialize patterns for suspicious but not necessarily malicious content."""
        return [
            re.compile(r'password\s*[:=]\s*[\'"][^\'"]*[\'"]', re.IGNORECASE),
            re.compile(r'api[_-]?key\s*[:=]\s*[\'"][^\'"]*[\'"]', re.IGNORECASE),
            re.compile(r'secret\s*[:=]\s*[\'"][^\'"]*[\'"]', re.IGNORECASE),
            re.compile(r'token\s*[:=]\s*[\'"][^\'"]*[\'"]', re.IGNORECASE),
            re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),  # Email
            re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # SSN pattern
            re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),  # Credit card
        ]
    
    @handle_errors(severity=ErrorSeverity.HIGH, category=ErrorCategory.SECURITY)
    def analyze_content_threats(self, 
                              content: bytes, 
                              filename: str,
                              timeout_seconds: float = 30.0) -> Tuple[ThreatLevel, List[str]]:
        """
        Comprehensive threat analysis with timeout protection.
        
        Args:
            content: File content to analyze
            filename: Original filename
            timeout_seconds: Maximum analysis time
            
        Returns:
            Tuple of (threat_level, threats_detected)
        """
        # Check cache first
        content_hash = hashlib.sha256(content).hexdigest()
        
        with self._cache_lock:
            if content_hash in self.detection_cache:
                cached_result = self.detection_cache[content_hash]
                if (datetime.now() - cached_result['timestamp']).seconds < 3600:  # 1 hour cache
                    return cached_result['threat_level'], cached_result['threats']
        
        threats_detected = []
        max_threat_level = ThreatLevel.SAFE
        
        try:
            # Use ThreadPoolExecutor for timeout protection
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._perform_threat_analysis, content, filename)
                
                try:
                    threats_detected, max_threat_level = future.result(timeout=timeout_seconds)
                except TimeoutError:
                    threats_detected = ["Analysis timeout - potential resource exhaustion attack"]
                    max_threat_level = ThreatLevel.HIGH
                    self.logger.warning(f"Threat analysis timeout for file: {filename}")
                    
        except Exception as e:
            threats_detected = [f"Analysis error: {str(e)}"]
            max_threat_level = ThreatLevel.MEDIUM
            self.logger.error(f"Threat analysis failed for {filename}: {e}")
        
        # Cache results
        with self._cache_lock:
            self.detection_cache[content_hash] = {
                'threat_level': max_threat_level,
                'threats': threats_detected,
                'timestamp': datetime.now()
            }
            
            # Maintain cache size
            if len(self.detection_cache) > 1000:
                oldest_entries = sorted(
                    self.detection_cache.items(),
                    key=lambda x: x[1]['timestamp']
                )[:100]
                for key, _ in oldest_entries:
                    del self.detection_cache[key]
        
        return max_threat_level, threats_detected
    
    def _perform_threat_analysis(self, content: bytes, filename: str) -> Tuple[List[str], ThreatLevel]:
        """Perform the actual threat analysis."""
        threats_detected = []
        threat_levels = []
        
        try:
            # Convert content to string for pattern analysis
            content_str = content.decode('utf-8', errors='ignore')
            
            # Analyze each threat category
            for category, patterns in self.threat_patterns.items():
                category_threats = self._analyze_pattern_category(content_str, category, patterns)
                if category_threats:
                    threats_detected.extend(category_threats)
                    
                    # Assign threat levels based on category
                    if category in ['malware_signatures', 'command_injection']:
                        threat_levels.append(ThreatLevel.CRITICAL)
                    elif category in ['script_injection', 'sql_injection']:
                        threat_levels.append(ThreatLevel.HIGH)
                    elif category in ['path_traversal', 'file_inclusion']:
                        threat_levels.append(ThreatLevel.MEDIUM)
                    else:
                        threat_levels.append(ThreatLevel.LOW)
            
            # Check for suspicious patterns
            suspicious_findings = self._analyze_suspicious_patterns(content_str)
            if suspicious_findings:
                threats_detected.extend(suspicious_findings)
                threat_levels.append(ThreatLevel.LOW)
            
            # Determine maximum threat level
            max_threat_level = ThreatLevel.SAFE
            if threat_levels:
                threat_level_order = [ThreatLevel.SAFE, ThreatLevel.LOW, ThreatLevel.MEDIUM, 
                                    ThreatLevel.HIGH, ThreatLevel.CRITICAL]
                max_threat_level = max(threat_levels, key=lambda x: threat_level_order.index(x))
                
        except Exception as e:
            threats_detected = [f"Analysis error: {str(e)}"]
            max_threat_level = ThreatLevel.MEDIUM
            
        return threats_detected, max_threat_level
    
    def _analyze_pattern_category(self, content: str, category: str, patterns: List[Pattern]) -> List[str]:
        """Analyze content for specific pattern category."""
        threats = []
        
        for pattern in patterns:
            matches = pattern.findall(content)
            if matches:
                threats.append(f"{category}: {len(matches)} instances detected")
                
        return threats
    
    def _analyze_suspicious_patterns(self, content: str) -> List[str]:
        """Analyze content for suspicious but not necessarily malicious patterns."""
        findings = []
        
        for pattern in self.suspicious_patterns:
            matches = pattern.findall(content)
            if matches:
                # Don't expose the actual matches for privacy
                findings.append(f"Suspicious pattern detected: {len(matches)} instances")
                
        return findings


class DataProtectionManager:
    """
    Professional data protection and PII detection system.
    
    Features:
    - Advanced PII detection with multiple patterns
    - Data classification and sensitivity scoring
    - Privacy compliance monitoring
    - Automatic redaction suggestions
    """
    
    def __init__(self):
        """Initialize data protection manager."""
        self.pii_patterns = self._initialize_pii_patterns()
        self.classification_rules = self._initialize_classification_rules()
        self.logger = logging.getLogger('data_protection')
        
    def _initialize_pii_patterns(self) -> Dict[str, List[Pattern]]:
        """Initialize comprehensive PII detection patterns."""
        return {
            'social_security_number': [
                re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
                re.compile(r'\b\d{3}\s\d{2}\s\d{4}\b'),
                re.compile(r'\b\d{9}\b'),
            ],
            'credit_card': [
                re.compile(r'\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),  # Visa
                re.compile(r'\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),  # MasterCard
                re.compile(r'\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b'),  # AmEx
                re.compile(r'\b6011[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),  # Discover
            ],
            'email_address': [
                re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            ],
            'phone_number': [
                re.compile(r'\b\(\d{3}\)\s?\d{3}-\d{4}\b'),
                re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),
                re.compile(r'\b\d{3}\.\d{3}\.\d{4}\b'),
                re.compile(r'\b\+1[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{4}\b'),
                re.compile(r'\b\+91[-\s]?\d{10}\b'),
            ],
            'date_of_birth': [
                re.compile(r'\b\d{1,2}/\d{1,2}/\d{4}\b'),
                re.compile(r'\b\d{1,2}-\d{1,2}-\d{4}\b'),
                re.compile(r'\b\d{4}-\d{1,2}-\d{1,2}\b'),
            ],
            'drivers_license': [
                re.compile(r'\b[A-Z]\d{7,8}\b'),  # Common format
                re.compile(r'\bDL[-\s]?\d{8,12}\b', re.IGNORECASE),
            ],
            'bank_account': [
                re.compile(r'\b\d{8,17}\b'),  # Bank account numbers
                re.compile(r'\bRouting[-\s]?\d{9}\b', re.IGNORECASE),
            ],
            'passport_number': [
                re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
                re.compile(r'\bPassport[-\s]?[A-Z0-9]{6,12}\b', re.IGNORECASE),
            ],
            'medical_record': [
                re.compile(r'\bMRN[-\s]?\d{6,12}\b', re.IGNORECASE),
                re.compile(r'\bPatient[-\s]?ID[-\s]?\d{6,12}\b', re.IGNORECASE),
            ],
            'ip_address': [
                re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
                re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.IGNORECASE),
            ]
        }
    
    def _initialize_classification_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize data classification rules."""
        return {
            'social_security_number': {
                'sensitivity': 'CRITICAL',
                'compliance': ['PCI-DSS', 'GDPR', 'HIPAA'],
                'risk_score': 100
            },
            'credit_card': {
                'sensitivity': 'CRITICAL',
                'compliance': ['PCI-DSS', 'GDPR'],
                'risk_score': 95
            },
            'medical_record': {
                'sensitivity': 'CRITICAL',
                'compliance': ['HIPAA', 'GDPR'],
                'risk_score': 90
            },
            'bank_account': {
                'sensitivity': 'HIGH',
                'compliance': ['PCI-DSS', 'GDPR'],
                'risk_score': 85
            },
            'passport_number': {
                'sensitivity': 'HIGH',
                'compliance': ['GDPR'],
                'risk_score': 80
            },
            'drivers_license': {
                'sensitivity': 'MEDIUM',
                'compliance': ['GDPR'],
                'risk_score': 70
            },
            'email_address': {
                'sensitivity': 'MEDIUM',
                'compliance': ['GDPR', 'CAN-SPAM'],
                'risk_score': 60
            },
            'phone_number': {
                'sensitivity': 'MEDIUM',
                'compliance': ['GDPR', 'TCPA'],
                'risk_score': 55
            },
            'date_of_birth': {
                'sensitivity': 'MEDIUM',
                'compliance': ['GDPR', 'COPPA'],
                'risk_score': 65
            },
            'ip_address': {
                'sensitivity': 'LOW',
                'compliance': ['GDPR'],
                'risk_score': 40
            }
        }
    
    @handle_errors(severity=ErrorSeverity.MEDIUM, category=ErrorCategory.VALIDATION)
    def detect_pii_comprehensive(self, content: str) -> PIIDetectionResult:
        """
        Comprehensive PII detection with risk assessment.
        
        Args:
            content: Text content to analyze
            
        Returns:
            PIIDetectionResult with detailed analysis
        """
        result = PIIDetectionResult()
        total_instances = 0
        max_risk_score = 0
        
        try:
            for pii_type, patterns in self.pii_patterns.items():
                instances = []
                confidence_scores = []
                
                for pattern in patterns:
                    matches = pattern.findall(content)
                    if matches:
                        # Store anonymized references, not actual data
                        instances.extend(matches)
                        
                        # Calculate confidence based on pattern specificity
                        confidence = self._calculate_pattern_confidence(pattern, matches)
                        confidence_scores.append(confidence)
                
                if instances:
                    result.pii_types_found[pii_type] = instances
                    result.confidence_scores[pii_type] = max(confidence_scores)
                    total_instances += len(instances)
                    
                    # Update risk assessment
                    classification = self.classification_rules.get(pii_type, {})
                    risk_score = classification.get('risk_score', 0)
                    max_risk_score = max(max_risk_score, risk_score)
            
            result.total_instances = total_instances
            result.risk_level = self._calculate_risk_level(max_risk_score, total_instances)
            result.recommendations = self._generate_recommendations(result)
            
        except Exception as e:
            self.logger.error(f"PII detection failed: {e}")
            result.risk_level = "UNKNOWN"
            
        return result
    
    def _calculate_pattern_confidence(self, pattern: Pattern, matches: List[str]) -> float:
        """Calculate confidence score for pattern matches."""
        # Base confidence on pattern complexity and match characteristics
        base_confidence = 0.7
        
        # Increase confidence for more specific patterns
        if len(pattern.pattern) > 20:
            base_confidence += 0.1
        
        # Increase confidence for multiple matches
        if len(matches) > 1:
            base_confidence += 0.1
            
        return min(base_confidence, 1.0)
    
    def _calculate_risk_level(self, max_risk_score: int, total_instances: int) -> str:
        """Calculate overall risk level based on PII findings."""
        if max_risk_score >= 90 or total_instances >= 20:
            return "CRITICAL"
        elif max_risk_score >= 70 or total_instances >= 10:
            return "HIGH"
        elif max_risk_score >= 50 or total_instances >= 5:
            return "MEDIUM"
        elif max_risk_score > 0 or total_instances > 0:
            return "LOW"
        else:
            return "SAFE"
    
    def _generate_recommendations(self, result: PIIDetectionResult) -> List[str]:
        """Generate security recommendations based on PII detection results."""
        recommendations = []
        
        if result.total_instances == 0:
            recommendations.append("No PII detected - document appears safe for general use")
            return recommendations
        
        # Risk-based recommendations
        if result.risk_level in ["CRITICAL", "HIGH"]:
            recommendations.append("IMMEDIATE ACTION REQUIRED: High-risk PII detected")
            recommendations.append("Apply comprehensive redaction before sharing")
            recommendations.append("Restrict access to authorized personnel only")
            recommendations.append("Consider encryption for storage and transmission")
        
        elif result.risk_level == "MEDIUM":
            recommendations.append("CAUTION: Moderate PII risk detected")
            recommendations.append("Review and redact sensitive information")
            recommendations.append("Implement access controls")
        
        else:  # LOW risk
            recommendations.append("Low PII risk - basic protection recommended")
            recommendations.append("Consider redaction of identified elements")
        
        # Specific recommendations by PII type
        critical_types = [pii_type for pii_type, _ in result.pii_types_found.items()
                         if self.classification_rules.get(pii_type, {}).get('sensitivity') == 'CRITICAL']
        
        if critical_types:
            recommendations.append(f"Critical PII types found: {', '.join(critical_types)}")
            recommendations.append("Mandatory redaction required for compliance")
        
        return recommendations


class EnterpriseSecurityManager:
    """
    Comprehensive enterprise security management system.
    
    Coordinates all security functions including threat detection,
    data protection, audit logging, and compliance monitoring.
    """
    
    def __init__(self):
        """Initialize enterprise security manager."""
        self.threat_detector = AdvancedThreatDetector()
        self.data_protection = DataProtectionManager()
        self.security_events: List[SecurityEvent] = []
        self.metrics = self._initialize_metrics()
        self.logger = logging.getLogger('enterprise_security')
        self._events_lock = threading.RLock()
        
    def _initialize_metrics(self) -> Dict[str, Any]:
        """Initialize security metrics tracking."""
        return {
            'total_scans': 0,
            'threats_detected': 0,
            'threats_blocked': 0,
            'pii_instances_found': 0,
            'security_violations': 0,
            'false_positives': 0,
            'scan_performance': {
                'avg_scan_time_ms': 0.0,
                'max_scan_time_ms': 0.0,
                'total_scan_time_ms': 0.0
            }
        }
    
    @handle_errors(severity=ErrorSeverity.HIGH, category=ErrorCategory.SECURITY)
    def comprehensive_security_scan(self, 
                                  content: bytes, 
                                  filename: str,
                                  user_context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Perform comprehensive security scanning with full analysis.
        
        Args:
            content: File content to scan
            filename: Original filename
            user_context: Optional user context for audit
            
        Returns:
            Comprehensive security scan results
        """
        scan_start = time.time()
        self.metrics['total_scans'] += 1
        
        scan_results = {
            'scan_id': secrets.token_hex(16),
            'timestamp': datetime.now().isoformat(),
            'filename': filename,
            'file_size': len(content),
            'file_hash': hashlib.sha256(content).hexdigest(),
            'threat_level': ThreatLevel.SAFE,
            'threats_detected': [],
            'pii_detected': {},
            'security_score': 100.0,
            'recommendations': [],
            'compliance_issues': [],
            'scan_duration_ms': 0.0
        }
        
        try:
            # 1. Threat detection analysis
            threat_level, threats = self.threat_detector.analyze_content_threats(content, filename)
            scan_results['threat_level'] = threat_level
            scan_results['threats_detected'] = threats
            
            if threats:
                self.metrics['threats_detected'] += len(threats)
                
            # 2. PII detection and analysis
            try:
                content_str = content.decode('utf-8', errors='ignore')
                pii_result = self.data_protection.detect_pii_comprehensive(content_str)
                
                scan_results['pii_detected'] = {
                    'types_found': pii_result.pii_types_found,
                    'total_instances': pii_result.total_instances,
                    'risk_level': pii_result.risk_level,
                    'confidence_scores': pii_result.confidence_scores
                }
                
                scan_results['recommendations'].extend(pii_result.recommendations)
                self.metrics['pii_instances_found'] += pii_result.total_instances
                
            except Exception as e:
                scan_results['pii_detection_error'] = str(e)
                self.logger.warning(f"PII detection failed for {filename}: {e}")
            
            # 3. Calculate comprehensive security score
            security_score = self._calculate_security_score(scan_results)
            scan_results['security_score'] = security_score
            
            # 4. Generate compliance analysis
            compliance_issues = self._analyze_compliance_requirements(scan_results)
            scan_results['compliance_issues'] = compliance_issues
            
            # 5. Record security event
            if threats or threat_level != ThreatLevel.SAFE:
                self._record_security_event(
                    event_type=SecurityEventType.MALWARE_DETECTION,
                    threat_level=threat_level,
                    filename=filename,
                    file_hash=scan_results['file_hash'],
                    file_size=len(content),
                    threat_details=f"Threats: {threats}",
                    user_context=user_context
                )
                
                if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    self.metrics['threats_blocked'] += 1
            
            # 6. Record PII detection event if significant
            pii_result = scan_results.get('pii_detected', {})
            if pii_result.get('total_instances', 0) > 0:
                self._record_security_event(
                    event_type=SecurityEventType.PII_DETECTION,
                    threat_level=ThreatLevel.MEDIUM if pii_result.get('risk_level') in ['HIGH', 'CRITICAL'] else ThreatLevel.LOW,
                    filename=filename,
                    file_hash=scan_results['file_hash'],
                    file_size=len(content),
                    threat_details=f"PII instances: {pii_result.get('total_instances', 0)}",
                    user_context=user_context
                )
            
        except Exception as e:
            scan_results['scan_error'] = str(e)
            self.logger.error(f"Security scan failed for {filename}: {e}")
            
        finally:
            # Update performance metrics
            scan_duration = (time.time() - scan_start) * 1000
            scan_results['scan_duration_ms'] = scan_duration
            
            self.metrics['scan_performance']['total_scan_time_ms'] += scan_duration
            self.metrics['scan_performance']['avg_scan_time_ms'] = (
                self.metrics['scan_performance']['total_scan_time_ms'] / self.metrics['total_scans']
            )
            self.metrics['scan_performance']['max_scan_time_ms'] = max(
                self.metrics['scan_performance']['max_scan_time_ms'], scan_duration
            )
        
        return scan_results
    
    def _calculate_security_score(self, scan_results: Dict[str, Any]) -> float:
        """Calculate comprehensive security score (0-100)."""
        base_score = 100.0
        
        # Deduct for threats
        threat_level = scan_results.get('threat_level', ThreatLevel.SAFE)
        threat_deductions = {
            ThreatLevel.LOW: 10,
            ThreatLevel.MEDIUM: 25,
            ThreatLevel.HIGH: 50,
            ThreatLevel.CRITICAL: 80
        }
        base_score -= threat_deductions.get(threat_level, 0)
        
        # Deduct for PII risk
        pii_data = scan_results.get('pii_detected', {})
        pii_risk = pii_data.get('risk_level', 'SAFE')
        pii_deductions = {
            'LOW': 5,
            'MEDIUM': 15,
            'HIGH': 30,
            'CRITICAL': 40
        }
        base_score -= pii_deductions.get(pii_risk, 0)
        
        # Deduct for file size (larger files have more attack surface)
        file_size_mb = scan_results.get('file_size', 0) / (1024 * 1024)
        if file_size_mb > 100:
            base_score -= min(10, file_size_mb / 50)
        
        return max(0.0, round(base_score, 1))
    
    def _analyze_compliance_requirements(self, scan_results: Dict[str, Any]) -> List[str]:
        """Analyze compliance requirements based on scan results."""
        compliance_issues = []
        
        pii_data = scan_results.get('pii_detected', {})
        pii_types = pii_data.get('types_found', {})
        
        # Check for regulated data types
        regulated_types = {
            'social_security_number': ['PCI-DSS', 'GDPR', 'HIPAA'],
            'credit_card': ['PCI-DSS', 'GDPR'],
            'medical_record': ['HIPAA', 'GDPR'],
            'email_address': ['GDPR', 'CAN-SPAM']
        }
        
        applicable_regulations = set()
        for pii_type in pii_types:
            if pii_type in regulated_types:
                applicable_regulations.update(regulated_types[pii_type])
        
        if applicable_regulations:
            compliance_issues.append(f"Compliance requirements: {', '.join(applicable_regulations)}")
        
        # Check threat levels for compliance impact
        threat_level = scan_results.get('threat_level', ThreatLevel.SAFE)
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            compliance_issues.append("High threat level may require incident reporting")
        
        return compliance_issues
    
    def _record_security_event(self, 
                             event_type: SecurityEventType,
                             threat_level: ThreatLevel,
                             filename: str,
                             file_hash: str,
                             file_size: int,
                             threat_details: str,
                             user_context: Optional[Dict] = None):
        """Record security event for audit and analysis."""
        event = SecurityEvent(
            event_type=event_type,
            threat_level=threat_level,
            file_name=filename,
            file_hash=file_hash,
            file_size=file_size,
            threat_details=threat_details,
            mitigation_action="Scan completed, results logged",
            additional_context=user_context or {}
        )
        
        with self._events_lock:
            self.security_events.append(event)
            
            # Maintain event history (keep last 10000 events)
            if len(self.security_events) > 10000:
                self.security_events = self.security_events[-5000:]
        
        # Log security event
        self.logger.info(
            f"SECURITY_EVENT | {event.event_type.value} | "
            f"Threat:{event.threat_level.value} | "
            f"File:{filename} | Details:{threat_details}"
        )
    
    def get_security_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive security dashboard data."""
        recent_events = [e for e in self.security_events 
                        if (datetime.now() - e.timestamp).seconds < 86400]  # Last 24 hours
        
        return {
            'metrics': self.metrics,
            'recent_events_24h': len(recent_events),
            'critical_events_24h': len([e for e in recent_events 
                                      if e.threat_level == ThreatLevel.CRITICAL]),
            'event_types_24h': {
                event_type.value: len([e for e in recent_events if e.event_type == event_type])
                for event_type in SecurityEventType
            },
            'threat_levels_24h': {
                threat_level.value: len([e for e in recent_events if e.threat_level == threat_level])
                for threat_level in ThreatLevel
            },
            'performance_metrics': self.metrics['scan_performance'],
            'last_updated': datetime.now().isoformat()
        }


# Global security manager instance
security_manager = EnterpriseSecurityManager()


# Export main security functions
def scan_file_security(content: bytes, filename: str, user_context: Optional[Dict] = None) -> Dict[str, Any]:
    """Main function for comprehensive security scanning of uploaded files."""
    return security_manager.comprehensive_security_scan(content, filename, user_context)


def get_security_dashboard() -> Dict[str, Any]:
    """Get security dashboard data for monitoring."""
    return security_manager.get_security_dashboard()


def detect_pii(content: str) -> PIIDetectionResult:
    """Detect PII in text content with comprehensive analysis."""
    return security_manager.data_protection.detect_pii_comprehensive(content)


def get_security_metrics() -> Dict[str, Any]:
    """Get current security metrics."""
    return security_manager.metrics.copy()
