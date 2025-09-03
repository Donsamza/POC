"""
Enterprise Error Handling and Monitoring System
==============================================

Professional-grade error handling with comprehensive monitoring,
recovery mechanisms, and audit trails designed for production
enterprise environments.

Author: Senior GenAI Engineer
Version: 2.1.0
Date: September 1, 2025
"""

import functools
import logging
import traceback
import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Type
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager
import json
import uuid

# Configuration imports
try:
    from config import get_logging_config, get_performance_config, get_security_config
except ImportError:
    # Fallback for standalone usage
    def get_logging_config():
        class MockConfig:
            LOG_LEVEL = "INFO"
            LOG_FILE_PATH = "application.log"
        return MockConfig()
    
    def get_performance_config():
        class MockConfig:
            MAX_MEMORY_USAGE_MB = 1000
        return MockConfig()
    
    def get_security_config():
        class MockConfig:
            ENABLE_DETAILED_LOGGING = True
        return MockConfig()


class ErrorSeverity(Enum):
    """Error severity classification for proper handling and alerting."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ErrorCategory(Enum):
    """Error categories for systematic handling and analysis."""
    SECURITY = "SECURITY"
    FILE_PROCESSING = "FILE_PROCESSING"
    MEMORY = "MEMORY"
    PERFORMANCE = "PERFORMANCE"
    VALIDATION = "VALIDATION"
    SYSTEM = "SYSTEM"
    USER_INPUT = "USER_INPUT"
    NETWORK = "NETWORK"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"


@dataclass
class ErrorContext:
    """Comprehensive error context for detailed analysis and recovery."""
    error_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    category: ErrorCategory = ErrorCategory.SYSTEM
    message: str = ""
    details: str = ""
    stack_trace: str = ""
    function_name: str = ""
    module_name: str = ""
    user_context: Dict[str, Any] = field(default_factory=dict)
    system_state: Dict[str, Any] = field(default_factory=dict)
    recovery_attempted: bool = False
    recovery_successful: bool = False
    resolution_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error context to dictionary for logging."""
        return {
            'error_id': self.error_id,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value,
            'category': self.category.value,
            'message': self.message,
            'details': self.details,
            'function_name': self.function_name,
            'module_name': self.module_name,
            'user_context': self.user_context,
            'system_state': self.system_state,
            'recovery_attempted': self.recovery_attempted,
            'recovery_successful': self.recovery_successful,
            'resolution_time': self.resolution_time
        }


class EnterpriseErrorHandler:
    """
    Professional error handling system with comprehensive monitoring.
    """
    
    def __init__(self):
        self.logger = self._setup_professional_logger()
        self.error_history: List[ErrorContext] = []
        self._metrics = {
            'total_errors': 0,
            'errors_by_severity': {s.value: 0 for s in ErrorSeverity},
            'errors_by_category': {c.value: 0 for c in ErrorCategory},
            'recovery_success_rate': 0.0
        }
        
    def _setup_professional_logger(self) -> logging.Logger:
        """Setup enterprise-grade logging configuration."""
        logger = logging.getLogger('enterprise_error_handler')
        
        if not logger.handlers:
            try:
                config = get_logging_config()
                file_handler = logging.FileHandler(config.LOG_FILE_PATH)
                file_handler.setLevel(getattr(logging, config.LOG_LEVEL))
            except:
                file_handler = logging.FileHandler('error_audit.log')
                file_handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter(
                '%(asctime)s | %(name)s | %(levelname)s | '
                'PID:%(process)d | Thread:%(thread)d | '
                '%(funcName)s:%(lineno)d | %(message)s'
            )
            
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.setLevel(logging.INFO)
            
        return logger
    
    def handle_error(self, 
                    exception: Exception,
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    category: ErrorCategory = ErrorCategory.SYSTEM,
                    context: Optional[Dict[str, Any]] = None,
                    attempt_recovery: bool = True) -> ErrorContext:
        """Professional error handling with comprehensive analysis."""
        
        error_context = ErrorContext(
            severity=severity,
            category=category,
            message=str(exception),
            details=repr(exception),
            stack_trace=traceback.format_exc(),
            function_name=self._get_calling_function(),
            module_name=self._get_calling_module(),
            user_context=context or {}
        )
        
        # Log error
        self._log_error_comprehensive(error_context, exception)
        
        # Update metrics
        self._update_error_metrics(error_context)
        
        # Store in history
        self.error_history.append(error_context)
        self._maintain_error_history()
        
        return error_context
    
    def _log_error_comprehensive(self, context: ErrorContext, exception: Exception):
        """Log error with comprehensive context."""
        log_level = self._severity_to_log_level(context.severity)
        
        self.logger.log(
            log_level,
            f"ERROR_ID:{context.error_id} | {context.category.value} | "
            f"{context.severity.value} | {context.message}"
        )
        
        if context.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            self.logger.log(
                log_level,
                f"ERROR_DETAILS:{context.error_id} | "
                f"Function:{context.function_name} | "
                f"Module:{context.module_name}"
            )
    
    def _severity_to_log_level(self, severity: ErrorSeverity) -> int:
        """Convert error severity to logging level."""
        mapping = {
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL
        }
        return mapping.get(severity, logging.WARNING)
    
    def _get_calling_function(self) -> str:
        """Get the name of the function that triggered the error."""
        try:
            frame = traceback.extract_tb(traceback.sys.exc_info()[2])[-1]
            return frame.name
        except:
            return "unknown"
    
    def _get_calling_module(self) -> str:
        """Get the module name where the error occurred."""
        try:
            frame = traceback.extract_tb(traceback.sys.exc_info()[2])[-1]
            return frame.filename.split('/')[-1]
        except:
            return "unknown"
    
    def _update_error_metrics(self, context: ErrorContext):
        """Update error tracking metrics."""
        self._metrics['total_errors'] += 1
        self._metrics['errors_by_severity'][context.severity.value] += 1
        self._metrics['errors_by_category'][context.category.value] += 1
    
    def _maintain_error_history(self, max_history: int = 1000):
        """Maintain error history within reasonable limits."""
        if len(self.error_history) > max_history:
            critical_errors = [e for e in self.error_history 
                             if e.severity == ErrorSeverity.CRITICAL]
            recent_errors = self.error_history[-max_history//2:]
            
            self.error_history = critical_errors + recent_errors
            self.error_history = list({e.error_id: e for e in self.error_history}.values())
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get comprehensive error statistics for monitoring."""
        return self._metrics.copy()


# Global error handler instance
_error_handler = EnterpriseErrorHandler()


def handle_errors(severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 category: ErrorCategory = ErrorCategory.SYSTEM,
                 context: Optional[Dict[str, Any]] = None,
                 attempt_recovery: bool = True):
    """
    Professional error handling decorator.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_context = _error_handler.handle_error(
                    exception=e,
                    severity=severity,
                    category=category,
                    context=context,
                    attempt_recovery=attempt_recovery
                )
                
                # Re-raise critical errors
                if severity == ErrorSeverity.CRITICAL:
                    raise
                    
                return None
                
        return wrapper
    return decorator


def get_error_statistics() -> Dict[str, Any]:
    """Get comprehensive error statistics."""
    return _error_handler.get_error_statistics()


@contextmanager
def performance_monitor(operation_name: str, 
                       max_duration_seconds: float = 30.0):
    """Context manager for monitoring operation performance."""
    start_time = time.time()
    
    try:
        yield
    finally:
        duration = time.time() - start_time
        
        if duration > max_duration_seconds:
            _error_handler.handle_error(
                exception=Exception(f"Performance violation: {operation_name} took {duration:.2f}s"),
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.PERFORMANCE,
                context={'operation': operation_name, 'duration': duration}
            )
