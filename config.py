"""
Enterprise Configuration Management System
=========================================

Professional-grade configuration management with environment-based settings,
validation, monitoring, and dynamic updates designed for enterprise
production environments.

Author: Senior GenAI Engineer
Version: 2.1.0
Date: September 1, 2025
"""

import os
import json
import logging
from pathlib import Path
from typing import Set, Dict, Any, List, Optional, Union, Type, Tuple
from dataclasses import dataclass, field, fields
from enum import Enum
import threading
from datetime import datetime


class Environment(Enum):
    """Deployment environment types."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class ConfigurationError(Exception):
    """Configuration-related errors."""
    pass


@dataclass
class SecurityConfig:
    """
    Enterprise security configuration with comprehensive protection measures.
    
    Designed for production environments with strict security requirements.
    """
    
    # File validation settings
    ALLOWED_EXTENSIONS: Set[str] = field(default_factory=lambda: {'.pdf'})
    ALLOWED_MIME_TYPES: Set[str] = field(default_factory=lambda: {'application/pdf'})
    MAX_FILE_SIZE_MB: int = 300
    MAX_FILE_SIZE_BYTES: int = field(init=False)
    
    # Security patterns for threat detection
    DANGEROUS_PATTERNS: Set[str] = field(default_factory=lambda: {
        # Directory traversal attacks
        '../', '..\\', '.\\', './',
        # Script injection attacks
        '<script', '</script>', 'javascript:', 'vbscript:', 'data:',
        # File protocol attacks
        'file://', 'ftp://', 'sftp://', 'smb://', 'http://', 'https://',
        # Event handler injection
        'onload=', 'onerror=', 'onclick=', 'onmouseover=', 'onfocus=',
        # Code execution attempts
        'eval(', 'exec(', 'system(', 'import os', '<?php', '<%', '%>', '<jsp:',
        # DOM manipulation
        'document.', 'window.', 'location.', 'history.', 'localStorage.',
        # Common attack vectors
        'alert(', 'confirm(', 'prompt(', 'console.log', 'setTimeout(',
        # SQL injection patterns
        'union select', 'drop table', 'insert into', 'delete from',
        # Command injection patterns
        '&&', '||', ';rm', ';del', '`', '$('
    })
    
    # Reserved filenames (Windows compatibility)
    RESERVED_FILENAMES: Set[str] = field(default_factory=lambda: {
        'con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5',
        'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5',
        'lpt6', 'lpt7', 'lpt8', 'lpt9', 'clock$'
    })
    
    # Filename validation
    MAX_FILENAME_LENGTH: int = 255
    ALLOWED_FILENAME_CHARS: str = r'[a-zA-Z0-9._\-\s]+'
    
    # Session management
    SESSION_TIMEOUT_MINUTES: int = 30
    MAX_CONCURRENT_SESSIONS: int = 100
    SESSION_SECURITY_HEADERS: Dict[str, str] = field(default_factory=lambda: {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'"
    })
    
    # Resource limits
    MEMORY_WARNING_THRESHOLD_MB: int = 500
    MEMORY_CRITICAL_THRESHOLD_MB: int = 800
    CPU_WARNING_THRESHOLD_PERCENT: int = 80
    CPU_CRITICAL_THRESHOLD_PERCENT: int = 95
    
    # Audit and compliance
    AUDIT_LOG_MAX_SIZE_MB: int = 100
    AUDIT_LOG_RETENTION_DAYS: int = 90
    ENABLE_DETAILED_LOGGING: bool = True
    LOG_SENSITIVE_OPERATIONS: bool = True
    
    # Rate limiting
    MAX_UPLOADS_PER_MINUTE: int = 10
    MAX_REDACTIONS_PER_MINUTE: int = 50
    MAX_API_CALLS_PER_HOUR: int = 1000
    
    # Encryption settings
    ENCRYPTION_ALGORITHM: str = "AES-256-GCM"
    KEY_ROTATION_DAYS: int = 90
    REQUIRE_ENCRYPTION_AT_REST: bool = True
    
    def __post_init__(self):
        """Post-initialization validation and computed fields."""
        self.MAX_FILE_SIZE_BYTES = self.MAX_FILE_SIZE_MB * 1024 * 1024
        
        # Validate configuration
        if self.MAX_FILE_SIZE_MB <= 0:
            raise ConfigurationError("MAX_FILE_SIZE_MB must be positive")
        if self.SESSION_TIMEOUT_MINUTES <= 0:
            raise ConfigurationError("SESSION_TIMEOUT_MINUTES must be positive")
        if not self.ALLOWED_EXTENSIONS:
            raise ConfigurationError("ALLOWED_EXTENSIONS cannot be empty")


@dataclass
class PDFProcessingConfig:
    """
    PDF processing configuration optimized for enterprise workloads.
    
    Balances performance, memory usage, and processing quality for
    production environments.
    """
    
    # Document limits
    MAX_PAGES_PER_DOCUMENT: int = 300
    MIN_PAGES_PER_DOCUMENT: int = 1
    LARGE_DOCUMENT_THRESHOLD_PAGES: int = 100
    
    # Performance settings
    MAX_PROCESSING_TIME_SECONDS: int = 300  # 5 minutes
    PROCESSING_TIMEOUT_WARNING_SECONDS: int = 180  # 3 minutes warning
    MEMORY_EFFICIENT_THRESHOLD_MB: int = 200
    ENABLE_PARALLEL_PROCESSING: bool = True
    MAX_WORKER_THREADS: int = 4
    
    # Processing quality settings
    TEXT_EXTRACTION_DPI: int = 150
    IMAGE_EXTRACTION_DPI: int = 300
    OCR_CONFIDENCE_THRESHOLD: float = 0.8
    ENABLE_OCR_FALLBACK: bool = True
    
    # Redaction appearance
    DEFAULT_REDACTION_COLOR: Tuple[float, float, float] = (0.0, 0.0, 0.0)  # Black
    REDACTION_COLORS: Dict[str, Tuple[float, float, float]] = field(default_factory=lambda: {
        'black': (0.0, 0.0, 0.0),
        'white': (1.0, 1.0, 1.0),
        'red': (1.0, 0.0, 0.0),
        'blue': (0.0, 0.0, 1.0),
        'gray': (0.5, 0.5, 0.5)
    })
    
    # Placeholder text options
    DEFAULT_PLACEHOLDER_TEXT: str = "[REDACTED]"
    PLACEHOLDER_OPTIONS: List[str] = field(default_factory=lambda: [
        "[REDACTED]",
        "[SENSITIVE INFO REMOVED]",
        "[CONFIDENTIAL]",
        "[CLASSIFIED]",
        "[PERSONAL DATA REMOVED]",
        "[PROPRIETARY INFORMATION]",
        "***REDACTED***",
        "░░░░░░░░░░",
        "■■■■■■■■■■",
        "XXXXXXXXXXXXX"
    ])
    
    # Text search options
    SEARCH_ALGORITHMS: List[str] = field(default_factory=lambda: [
        'exact_match',
        'case_insensitive',
        'whole_word',
        'regex',
        'fuzzy_match'
    ])
    
    # Image processing
    IMAGE_REDACTION_MODES: List[str] = field(default_factory=lambda: [
        'replace_with_black',
        'replace_with_white',
        'replace_with_pattern',
        'blur_content',
        'remove_completely'
    ])
    
    IMAGE_DETECTION_CONFIDENCE: float = 0.9
    MIN_IMAGE_SIZE_PIXELS: int = 100
    
    # Output quality
    OUTPUT_COMPRESSION_LEVEL: int = 6  # 0-9 scale
    PRESERVE_METADATA: bool = False  # Security: strip metadata
    PRESERVE_ANNOTATIONS: bool = False  # Security: strip annotations
    ENABLE_PDF_A_COMPLIANCE: bool = True


@dataclass
class UserInterfaceConfig:
    """
    User interface configuration for optimal user experience.
    
    Designed for professional enterprise environments with
    accessibility and usability requirements.
    """
    
    # Application branding
    PAGE_TITLE: str = "Enterprise PDF Redaction Suite"
    PAGE_ICON: str = "🔒"
    COMPANY_NAME: str = "Enterprise Solutions"
    APPLICATION_VERSION: str = "2.1.0"
    
    # Layout settings
    LAYOUT: str = "wide"
    SIDEBAR_STATE: str = "expanded"
    THEME: str = "light"
    
    # Professional color scheme
    PRIMARY_COLOR: str = "#1f4e79"  # Professional blue
    SECONDARY_COLOR: str = "#2c5aa0"
    SUCCESS_COLOR: str = "#28a745"
    WARNING_COLOR: str = "#ffc107"
    ERROR_COLOR: str = "#dc3545"
    INFO_COLOR: str = "#17a2b8"
    
    # Accessibility settings
    HIGH_CONTRAST_MODE: bool = False
    LARGE_FONT_MODE: bool = False
    SCREEN_READER_SUPPORT: bool = True
    KEYBOARD_NAVIGATION: bool = True
    
    # User feedback messages
    MESSAGES: Dict[str, str] = field(default_factory=lambda: {
        'file_upload_success': "✅ Document loaded successfully",
        'file_upload_error': "❌ Failed to load document",
        'invalid_file_type': "❌ Invalid file type. Only PDF files are supported.",
        'file_too_large': "❌ File exceeds maximum size limit",
        'redaction_success': "✅ Redaction applied successfully",
        'redaction_error': "❌ Redaction operation failed",
        'no_matches_found': "ℹ️ No matches found for the specified criteria",
        'processing_complete': "✅ Processing completed successfully",
        'session_cleared': "✅ Session cleared and resources freed",
        'security_scan_complete': "🔍 Security scan completed",
        'pii_detected': "⚠️ Personally identifiable information detected",
        'compliance_check_complete': "📋 Compliance check completed"
    })
    
    # Help text and tooltips
    HELP_TEXT: Dict[str, str] = field(default_factory=lambda: {
        'file_upload': "Upload a PDF document to begin redaction. Maximum size: 300MB",
        'text_search': "Enter text, patterns, or keywords to locate and redact",
        'replacement_text': "Text that will appear in place of redacted content",
        'page_selection': "Choose specific pages or ranges to process",
        'case_sensitive': "Enable for exact case matching during search",
        'regex_mode': "Use regular expressions for advanced pattern matching",
        'preview_mode': "Preview matches before applying redactions",
        'batch_processing': "Process multiple redaction patterns simultaneously"
    })
    
    # Progress indicators
    ENABLE_PROGRESS_BARS: bool = True
    SHOW_DETAILED_PROGRESS: bool = True
    PROGRESS_UPDATE_INTERVAL_MS: int = 500
    
    # Export options
    EXPORT_FORMATS: List[str] = field(default_factory=lambda: [
        'pdf',
        'pdf_a',  # PDF/A for archival
        'audit_report'  # Processing audit report
    ])
    
    # Dashboard settings
    ENABLE_ANALYTICS_DASHBOARD: bool = True
    REFRESH_INTERVAL_SECONDS: int = 30
    MAX_CHART_DATA_POINTS: int = 100


@dataclass
class LoggingConfig:
    """
    Enterprise logging configuration for audit and monitoring.
    
    Provides comprehensive logging for security, compliance,
    and operational monitoring requirements.
    """
    
    # Log levels
    LOG_LEVEL: str = "INFO"
    SECURITY_LOG_LEVEL: str = "INFO"
    AUDIT_LOG_LEVEL: str = "INFO"
    PERFORMANCE_LOG_LEVEL: str = "WARNING"
    
    # Log file settings
    LOG_FILE_PATH: str = "logs/application.log"
    SECURITY_LOG_PATH: str = "logs/security.log"
    AUDIT_LOG_PATH: str = "logs/audit.log"
    ERROR_LOG_PATH: str = "logs/errors.log"
    
    # File rotation
    MAX_LOG_FILE_SIZE_MB: int = 50
    LOG_BACKUP_COUNT: int = 10
    COMPRESS_ROTATED_LOGS: bool = True
    
    # Log format
    LOG_FORMAT: str = (
        "%(asctime)s | %(name)s | %(levelname)s | "
        "PID:%(process)d | Thread:%(thread)d | "
        "%(funcName)s:%(lineno)d | %(message)s"
    )
    DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
    
    # Audit events to log
    AUDIT_EVENTS: Set[str] = field(default_factory=lambda: {
        'file_upload', 'file_validation', 'security_scan', 'threat_detection',
        'text_search', 'redaction_applied', 'image_removal', 'area_redaction',
        'pdf_export', 'session_start', 'session_end', 'configuration_change',
        'user_action', 'system_event', 'error_occurrence', 'performance_alert'
    })
    
    # Log filtering
    EXCLUDE_PATTERNS: List[str] = field(default_factory=lambda: [
        'healthcheck',
        'static_file_access',
        'favicon_request'
    ])
    
    # Security logging
    LOG_SECURITY_HEADERS: bool = True
    LOG_USER_AGENTS: bool = True
    LOG_IP_ADDRESSES: bool = True
    MASK_SENSITIVE_DATA: bool = True
    
    # Performance logging
    LOG_SLOW_OPERATIONS: bool = True
    SLOW_OPERATION_THRESHOLD_MS: int = 1000
    LOG_MEMORY_USAGE: bool = True
    MEMORY_LOGGING_INTERVAL_MINUTES: int = 5


@dataclass
class PerformanceConfig:
    """
    Performance optimization configuration for enterprise workloads.
    
    Balances throughput, latency, and resource utilization for
    production environments.
    """
    
    # Memory management
    MAX_MEMORY_USAGE_MB: int = 2048  # 2GB
    MEMORY_WARNING_THRESHOLD_MB: int = 1536  # 1.5GB
    GARBAGE_COLLECTION_THRESHOLD: int = 100
    ENABLE_MEMORY_MONITORING: bool = True
    
    # Processing limits
    MAX_CONCURRENT_OPERATIONS: int = 10
    MAX_QUEUE_SIZE: int = 100
    OPERATION_TIMEOUT_SECONDS: int = 300
    
    # Chunk processing
    CHUNK_SIZE_BYTES: int = 1024 * 1024  # 1MB
    ENABLE_STREAMING_PROCESSING: bool = True
    STREAM_BUFFER_SIZE_MB: int = 10
    
    # Caching
    ENABLE_RESULT_CACHING: bool = True
    CACHE_SIZE_MB: int = 256
    CACHE_TTL_SECONDS: int = 3600  # 1 hour
    CACHE_CLEANUP_INTERVAL_MINUTES: int = 30
    
    # Database/Storage performance
    CONNECTION_POOL_SIZE: int = 20
    CONNECTION_TIMEOUT_SECONDS: int = 30
    QUERY_TIMEOUT_SECONDS: int = 60
    
    # Network settings
    NETWORK_TIMEOUT_SECONDS: int = 30
    MAX_RETRIES: int = 3
    RETRY_DELAY_SECONDS: int = 1
    
    # Monitoring
    ENABLE_PERFORMANCE_METRICS: bool = True
    METRICS_COLLECTION_INTERVAL_SECONDS: int = 60
    PERFORMANCE_ALERT_THRESHOLD_PERCENT: int = 85


@dataclass
class ComplianceConfig:
    """
    Compliance and regulatory configuration.
    
    Ensures adherence to industry standards and regulations.
    """
    
    # Regulatory frameworks
    ENABLED_FRAMEWORKS: Set[str] = field(default_factory=lambda: {
        'GDPR',      # General Data Protection Regulation
        'HIPAA',     # Health Insurance Portability and Accountability Act
        'PCI_DSS',   # Payment Card Industry Data Security Standard
        'SOX',       # Sarbanes-Oxley Act
        'ISO_27001'  # Information Security Management
    })
    
    # Data retention
    DATA_RETENTION_DAYS: int = 2555  # 7 years
    AUDIT_LOG_RETENTION_DAYS: int = 2555
    METADATA_RETENTION_DAYS: int = 90
    
    # Privacy settings
    ANONYMIZE_PII: bool = True
    ENCRYPT_SENSITIVE_DATA: bool = True
    REQUIRE_DATA_CLASSIFICATION: bool = True
    
    # Audit requirements
    REQUIRE_DUAL_APPROVAL: bool = False  # For sensitive operations
    ENABLE_TAMPER_DETECTION: bool = True
    GENERATE_COMPLIANCE_REPORTS: bool = True
    
    # Data subject rights (GDPR)
    ENABLE_RIGHT_TO_ACCESS: bool = True
    ENABLE_RIGHT_TO_RECTIFICATION: bool = True
    ENABLE_RIGHT_TO_ERASURE: bool = True
    ENABLE_DATA_PORTABILITY: bool = True


class EnvironmentConfigurationManager:
    """
    Professional configuration management with environment-specific settings.
    
    Provides centralized configuration with validation, monitoring,
    and dynamic updates for enterprise environments.
    """
    
    def __init__(self, environment: Optional[Environment] = None):
        """
        Initialize configuration manager.
        
        Args:
            environment: Target environment, auto-detected if None
        """
        self.environment = environment or self._detect_environment()
        self.config_lock = threading.RLock()
        self.logger = self._setup_logger()
        
        # Initialize configurations
        self.security = SecurityConfig()
        self.pdf_processing = PDFProcessingConfig()
        self.ui = UserInterfaceConfig()
        self.logging = LoggingConfig()
        self.performance = PerformanceConfig()
        self.compliance = ComplianceConfig()
        
        # Apply environment-specific overrides
        self._apply_environment_overrides()
        
        # Load external configuration
        self._load_external_configuration()
        
        # Validate configuration
        self._validate_configuration()
        
        self.logger.info(f"Configuration initialized for environment: {self.environment.value}")
    
    def _detect_environment(self) -> Environment:
        """Auto-detect deployment environment."""
        env_var = os.getenv('ENVIRONMENT', '').lower()
        
        environment_mapping = {
            'dev': Environment.DEVELOPMENT,
            'development': Environment.DEVELOPMENT,
            'test': Environment.TESTING,
            'testing': Environment.TESTING,
            'stage': Environment.STAGING,
            'staging': Environment.STAGING,
            'prod': Environment.PRODUCTION,
            'production': Environment.PRODUCTION
        }
        
        detected_env = environment_mapping.get(env_var, Environment.PRODUCTION)
        
        # Additional heuristics
        if 'pytest' in os.getenv('_', ''):
            detected_env = Environment.TESTING
        elif os.path.exists('.git'):
            detected_env = Environment.DEVELOPMENT
        
        return detected_env
    
    def _setup_logger(self) -> logging.Logger:
        """Setup configuration manager logger."""
        logger = logging.getLogger('config_manager')
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
            ))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        
        return logger
    
    def _apply_environment_overrides(self):
        """Apply environment-specific configuration overrides."""
        with self.config_lock:
            if self.environment == Environment.DEVELOPMENT:
                # Development environment settings
                self.security.MAX_FILE_SIZE_MB = 50
                self.security.SESSION_TIMEOUT_MINUTES = 60
                self.security.ENABLE_DETAILED_LOGGING = True
                self.pdf_processing.MAX_PROCESSING_TIME_SECONDS = 120
                self.logging.LOG_LEVEL = "DEBUG"
                self.performance.ENABLE_RESULT_CACHING = False
                
            elif self.environment == Environment.TESTING:
                # Testing environment settings
                self.security.MAX_FILE_SIZE_MB = 10
                self.security.SESSION_TIMEOUT_MINUTES = 15
                self.pdf_processing.MAX_PROCESSING_TIME_SECONDS = 60
                self.logging.LOG_LEVEL = "DEBUG"
                self.performance.MAX_MEMORY_USAGE_MB = 512
                
            elif self.environment == Environment.STAGING:
                # Staging environment (production-like)
                self.security.MAX_FILE_SIZE_MB = 200
                self.logging.LOG_LEVEL = "INFO"
                self.performance.ENABLE_PERFORMANCE_METRICS = True
                
            elif self.environment == Environment.PRODUCTION:
                # Production environment (secure defaults)
                self.security.ENABLE_DETAILED_LOGGING = True
                self.logging.LOG_LEVEL = "WARNING"
                self.performance.ENABLE_PERFORMANCE_METRICS = True
                self.compliance.REQUIRE_DUAL_APPROVAL = True
    
    def _load_external_configuration(self):
        """Load configuration from external sources."""
        config_files = [
            'config.json',
            f'config_{self.environment.value}.json',
            os.getenv('CONFIG_FILE', '')
        ]
        
        for config_file in config_files:
            if config_file and Path(config_file).exists():
                try:
                    with open(config_file, 'r') as f:
                        external_config = json.load(f)
                    
                    self._merge_external_config(external_config)
                    self.logger.info(f"Loaded external configuration: {config_file}")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to load config file {config_file}: {e}")
        
        # Load from environment variables
        self._load_environment_variables()
    
    def _merge_external_config(self, external_config: Dict[str, Any]):
        """Merge external configuration with current settings."""
        with self.config_lock:
            for section_name, section_config in external_config.items():
                if hasattr(self, section_name):
                    section_obj = getattr(self, section_name)
                    
                    for key, value in section_config.items():
                        if hasattr(section_obj, key):
                            # Type validation
                            field_type = type(getattr(section_obj, key))
                            try:
                                if field_type == set and isinstance(value, list):
                                    value = set(value)
                                elif field_type != type(value):
                                    value = field_type(value)
                                
                                setattr(section_obj, key, value)
                                
                            except (ValueError, TypeError) as e:
                                self.logger.warning(
                                    f"Invalid config value for {section_name}.{key}: {e}"
                                )
    
    def _load_environment_variables(self):
        """Load configuration from environment variables."""
        env_mappings = {
            'MAX_FILE_SIZE_MB': ('security', 'MAX_FILE_SIZE_MB', int),
            'SESSION_TIMEOUT': ('security', 'SESSION_TIMEOUT_MINUTES', int),
            'MAX_PAGES': ('pdf_processing', 'MAX_PAGES_PER_DOCUMENT', int),
            'LOG_LEVEL': ('logging', 'LOG_LEVEL', str),
            'MAX_MEMORY_MB': ('performance', 'MAX_MEMORY_USAGE_MB', int),
            'CACHE_SIZE_MB': ('performance', 'CACHE_SIZE_MB', int),
        }
        
        with self.config_lock:
            for env_var, (section, attribute, type_func) in env_mappings.items():
                value = os.getenv(env_var)
                if value is not None:
                    try:
                        typed_value = type_func(value)
                        section_obj = getattr(self, section)
                        setattr(section_obj, attribute, typed_value)
                        
                        self.logger.info(f"Applied environment override: {env_var}={typed_value}")
                        
                    except (ValueError, TypeError) as e:
                        self.logger.warning(f"Invalid environment variable {env_var}: {e}")
    
    def _validate_configuration(self):
        """Validate configuration settings for consistency and security."""
        validations = [
            self._validate_security_config,
            self._validate_pdf_config,
            self._validate_performance_config,
            self._validate_logging_config
        ]
        
        for validation_func in validations:
            try:
                validation_func()
            except ConfigurationError as e:
                self.logger.error(f"Configuration validation failed: {e}")
                raise
    
    def _validate_security_config(self):
        """Validate security configuration."""
        if self.security.MAX_FILE_SIZE_MB <= 0:
            raise ConfigurationError("MAX_FILE_SIZE_MB must be positive")
        
        if self.security.SESSION_TIMEOUT_MINUTES <= 0:
            raise ConfigurationError("SESSION_TIMEOUT_MINUTES must be positive")
        
        if not self.security.ALLOWED_EXTENSIONS:
            raise ConfigurationError("ALLOWED_EXTENSIONS cannot be empty")
        
        # Production-specific validations
        if self.environment == Environment.PRODUCTION:
            if self.security.SESSION_TIMEOUT_MINUTES > 60:
                self.logger.warning("Long session timeout in production environment")
            
            if self.security.MAX_FILE_SIZE_MB > 500:
                self.logger.warning("Large file size limit in production environment")
    
    def _validate_pdf_config(self):
        """Validate PDF processing configuration."""
        if self.pdf_processing.MAX_PAGES_PER_DOCUMENT <= 0:
            raise ConfigurationError("MAX_PAGES_PER_DOCUMENT must be positive")
        
        if self.pdf_processing.MAX_PROCESSING_TIME_SECONDS <= 0:
            raise ConfigurationError("MAX_PROCESSING_TIME_SECONDS must be positive")
        
        if not (0 <= self.pdf_processing.OUTPUT_COMPRESSION_LEVEL <= 9):
            raise ConfigurationError("OUTPUT_COMPRESSION_LEVEL must be between 0 and 9")
    
    def _validate_performance_config(self):
        """Validate performance configuration."""
        if self.performance.MAX_MEMORY_USAGE_MB <= 0:
            raise ConfigurationError("MAX_MEMORY_USAGE_MB must be positive")
        
        if self.performance.MAX_CONCURRENT_OPERATIONS <= 0:
            raise ConfigurationError("MAX_CONCURRENT_OPERATIONS must be positive")
        
        # Check memory thresholds
        if self.performance.MEMORY_WARNING_THRESHOLD_MB >= self.performance.MAX_MEMORY_USAGE_MB:
            raise ConfigurationError("MEMORY_WARNING_THRESHOLD_MB must be less than MAX_MEMORY_USAGE_MB")
    
    def _validate_logging_config(self):
        """Validate logging configuration."""
        valid_log_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        
        if self.logging.LOG_LEVEL not in valid_log_levels:
            raise ConfigurationError(f"Invalid LOG_LEVEL: {self.logging.LOG_LEVEL}")
        
        if self.logging.MAX_LOG_FILE_SIZE_MB <= 0:
            raise ConfigurationError("MAX_LOG_FILE_SIZE_MB must be positive")
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get comprehensive configuration summary."""
        return {
            'environment': self.environment.value,
            'timestamp': datetime.now().isoformat(),
            'sections': {
                'security': {
                    'max_file_size_mb': self.security.MAX_FILE_SIZE_MB,
                    'session_timeout_minutes': self.security.SESSION_TIMEOUT_MINUTES,
                    'allowed_extensions': list(self.security.ALLOWED_EXTENSIONS)
                },
                'pdf_processing': {
                    'max_pages': self.pdf_processing.MAX_PAGES_PER_DOCUMENT,
                    'max_processing_time': self.pdf_processing.MAX_PROCESSING_TIME_SECONDS,
                    'parallel_processing': self.pdf_processing.ENABLE_PARALLEL_PROCESSING
                },
                'performance': {
                    'max_memory_mb': self.performance.MAX_MEMORY_USAGE_MB,
                    'max_concurrent_ops': self.performance.MAX_CONCURRENT_OPERATIONS,
                    'caching_enabled': self.performance.ENABLE_RESULT_CACHING
                },
                'logging': {
                    'log_level': self.logging.LOG_LEVEL,
                    'audit_events': len(self.logging.AUDIT_EVENTS)
                }
            }
        }
    
    def export_configuration(self, file_path: Optional[str] = None) -> str:
        """Export current configuration to JSON."""
        config_data = {}
        
        for section_name in ['security', 'pdf_processing', 'ui', 'logging', 'performance', 'compliance']:
            section_obj = getattr(self, section_name)
            section_data = {}
            
            for field in fields(section_obj):
                value = getattr(section_obj, field.name)
                
                # Handle special types
                if isinstance(value, set):
                    value = list(value)
                elif isinstance(value, tuple):
                    value = list(value)
                
                section_data[field.name] = value
            
            config_data[section_name] = section_data
        
        config_json = json.dumps(config_data, indent=2, default=str)
        
        if file_path:
            with open(file_path, 'w') as f:
                f.write(config_json)
            self.logger.info(f"Configuration exported to: {file_path}")
        
        return config_json


# Global configuration manager instance
config_manager = EnvironmentConfigurationManager()


# Convenience functions for accessing configuration
def get_security_config() -> SecurityConfig:
    """Get security configuration."""
    return config_manager.security


def get_pdf_config() -> PDFProcessingConfig:
    """Get PDF processing configuration."""
    return config_manager.pdf_processing


def get_ui_config() -> UserInterfaceConfig:
    """Get UI configuration."""
    return config_manager.ui


def get_logging_config() -> LoggingConfig:
    """Get logging configuration."""
    return config_manager.logging


def get_performance_config() -> PerformanceConfig:
    """Get performance configuration."""
    return config_manager.performance


def get_compliance_config() -> ComplianceConfig:
    """Get compliance configuration."""
    return config_manager.compliance


def get_environment() -> Environment:
    """Get current environment."""
    return config_manager.environment


def get_config_summary() -> Dict[str, Any]:
    """Get configuration summary."""
    return config_manager.get_configuration_summary()


def export_config(file_path: Optional[str] = None) -> str:
    """Export configuration to JSON."""
    return config_manager.export_configuration(file_path)
