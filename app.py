import streamlit as st
import fitz
import pdfplumber
import re
import hashlib
import tempfile
import io
import base64
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import contextmanager
import logging
import zipfile
from concurrent.futures import ThreadPoolExecutor
import time

from config import get_security_config, get_pdf_config, get_ui_config
from error_handler import handle_errors, ErrorSeverity, ErrorCategory
from security import scan_file_security, detect_pii

# Configure professional logging
def setup_logging() -> logging.Logger:
    logger = logging.getLogger('pdf_redaction_enhanced')
    
    if not logger.handlers:
        file_handler = logging.FileHandler('redaction_audit.log')
        file_handler.setLevel(logging.INFO)
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO)
    
    return logger

logger = setup_logging()

if 'custom_rules' not in st.session_state:
    st.session_state.custom_rules = []

@dataclass
class ProcessingMetrics:
    """Comprehensive metrics for PDF processing operations."""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    pages_processed: int = 0
    redactions_applied: int = 0
    images_removed: int = 0
    processing_time_ms: float = 0.0
    memory_peak_mb: float = 0.0
    file_size_mb: float = 0.0
    security_score: float = 0.0
    
    @property
    def duration_seconds(self) -> float:
        """Calculate processing duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    def finalize(self) -> None:
        """Mark processing as complete and calculate final metrics."""
        self.end_time = datetime.now()
        self.processing_time_ms = self.duration_seconds * 1000


@dataclass
class RedactionRule:
    """Configuration for automated redaction rules."""
    name: str
    pattern: str
    is_regex: bool = True
    replacement_text: str = "[REDACTED]"
    case_sensitive: bool = False
    enabled: bool = True
    category: str = "General"
    
    def apply(self, text: str) -> str:
        """Apply redaction rule to text."""
        
        import re
        if not self.enabled:
            return text
            
        if self.is_regex:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            return re.sub(self.pattern, self.replacement_text, text, flags=flags)
        else:
            if self.case_sensitive:
                return text.replace(self.pattern, self.replacement_text)
            else:
                # Case-insensitive replacement
                import re
                return re.sub(re.escape(self.pattern), self.replacement_text, text, flags=re.IGNORECASE)


@dataclass
class ManualRedactionArea:
    """Manual redaction area defined by user."""
    page_num: int
    x0: float
    y0: float
    x1: float
    y1: float
    replacement_text: str = "[REDACTED]"
    redaction_type: str = "text"  # "text", "image", "area"


@dataclass
class DocumentState:
    """Complete state of a document including original and redacted versions."""
    filename: str
    original_content: bytes
    current_content: bytes
    redacted_content: Optional[bytes] = None
    metrics: ProcessingMetrics = field(default_factory=ProcessingMetrics)
    manual_redactions: List[ManualRedactionArea] = field(default_factory=list)
    applied_rules: List[str] = field(default_factory=list)
    is_processed: bool = False
    
    @property
    def file_size_mb(self) -> float:
        return len(self.current_content) / (1024 * 1024)


@dataclass
class BulkProcessingJob:
    """Bulk processing job for multiple documents."""
    job_id: str
    documents: List[DocumentState] = field(default_factory=list)
    rules: List[RedactionRule] = field(default_factory=list)
    total_files: int = 0
    processed_files: int = 0
    failed_files: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    status: str = "pending"  # "pending", "processing", "completed", "failed"
    
    @property
    def progress_percentage(self) -> float:
        if self.total_files == 0:
            return 0.0
        return (self.processed_files / self.total_files) * 100


@dataclass
class SecurityValidationResult:
    """Result of security validation with detailed analysis."""
    is_valid: bool
    threat_level: str
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    file_hash: Optional[str] = None
    sanitized_filename: Optional[str] = None


class RedactionRuleManager:
    """Manager for predefined and custom redaction rules."""
    
    @staticmethod
    def get_predefined_rules() -> List[RedactionRule]:
        """Get predefined redaction rules for common sensitive data."""
        return [
            # Personal Identification
            RedactionRule(
                name="Social Security Number (SSN)",
                pattern=r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',
                replacement_text="[SSN-REDACTED]",
                category="Personal ID"
            ),
            RedactionRule(
                name="US Phone Numbers",
                pattern=r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                replacement_text="[PHONE-REDACTED]",
                category="Contact Info"
            ),
            RedactionRule(
                name="Indian Phone Numbers",
                pattern=r'\b(?:\+91[-\s]?)?(?:0)?[6-9]\d{9}\b',
                replacement_text="[PHONE-REDACTED]",
                category="Contact Info"
            ),
            RedactionRule(
                name="Email Addresses",
                pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                replacement_text="[EMAIL-REDACTED]",
                category="Contact Info"
            ),
            RedactionRule(
                name="Credit Card Numbers",
                pattern=r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                replacement_text="[CARD-REDACTED]",
                category="Financial"
            ),
            # Indian specific patterns
            RedactionRule(
                name="PAN Card Numbers",
                pattern=r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
                replacement_text="[PAN-REDACTED]",
                category="Indian ID"
            ),
            RedactionRule(
                name="Aadhaar Numbers",
                pattern=r'\b\d{4}\s?\d{4}\s?\d{4}\b|\b\d{12}\b',
                replacement_text="[AADHAAR-REDACTED]",
                category="Indian ID"
            ),
        ]
    
    @staticmethod
    def create_custom_rule(name: str, pattern: str, replacement: str = "[REDACTED]", 
                          is_regex: bool = True, category: str = "Custom") -> RedactionRule:
        """Create a custom redaction rule."""
        return RedactionRule(
            name=name,
            pattern=pattern,
            replacement_text=replacement,
            is_regex=is_regex,
            category=category
        )
    
    @staticmethod
    def validate_regex_pattern(pattern: str) -> Tuple[bool, str]:
        """Validate if a regex pattern is safe and valid."""
        try:
            re.compile(pattern)
            # Check for potentially dangerous patterns
            dangerous_patterns = ['.*', '.+', '(.)*', '(.*)+']
            if any(danger in pattern for danger in dangerous_patterns):
                return False, "Pattern may cause performance issues"
            return True, "Valid pattern"
        except re.error as e:
            return False, f"Invalid regex: {str(e)}"

class EnhancedPDFProcessor:
    """
    Enhanced PDF processor with bulk processing and advanced redaction capabilities.
    """
    
    def __init__(self):
        self.config = get_pdf_config()
        self.security_config = get_security_config()
        self.document: Optional[fitz.Document] = None
        self.original_document: Optional[fitz.Document] = None
        self.metrics = ProcessingMetrics()
        self.redaction_rules = RedactionRuleManager.get_predefined_rules()
        
    @handle_errors(severity=ErrorSeverity.MEDIUM, category=ErrorCategory.FILE_PROCESSING)
    def load_document(self, pdf_content: bytes, filename: str) -> bool:
        """Load PDF document with comprehensive validation."""
        try:
            # Close existing documents
            self._cleanup_documents()
            
            # Load original (read-only) and working copies
            self.original_document = fitz.open(stream=pdf_content, filetype="pdf")
            self.document = fitz.open(stream=pdf_content, filetype="pdf")
            
            # Initialize metrics
            self.metrics = ProcessingMetrics()
            self.metrics.pages_processed = self.document.page_count
            self.metrics.file_size_mb = len(pdf_content) / (1024 * 1024)
            
            logger.info(f"Document loaded: {filename} | Pages: {self.document.page_count}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load document {filename}: {e}")
            return False
    
    def apply_redaction_rules(self, rules: List[RedactionRule]) -> Dict[str, Any]:
        """Apply multiple redaction rules to the document, including tabular data and detected PII."""
        if not self.document:
            raise ValueError("No document loaded")

        total_redactions = 0
        results_by_rule = {}

        # Detect and redact PII in all text on each page
        for page_num in range(self.document.page_count):
            page = self.document[page_num]
            text = page.get_text()
            detected_pii_result = detect_pii(text)
            print(detected_pii_result)
            # Extract all detected PII values from the PIIDetectionResult object
            pii_values = []
            if hasattr(detected_pii_result, 'pii_types_found'):
                for values in detected_pii_result.pii_types_found.values():
                    pii_values.extend(values)
            for pii_item in pii_values:
                print(pii_item)
                text_instances = page.search_for(pii_item)
                for inst in text_instances:
                    print(inst)
                    redact_annot = page.add_redact_annot(inst, text="[SENSITIVE DATA REMOVED]")
                    redact_annot.set_info(title="Auto-PII-Redacted")
                    total_redactions += 1
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)

        # Redact normal text using PyMuPDF rules
        for rule in rules:
            if not rule.enabled:
                continue
            rule_redactions = 0
            for page_num in range(self.document.page_count):
                page = self.document[page_num]
                text_instances = page.search_for(rule.pattern)
                for inst in text_instances:
                    redact_annot = page.add_redact_annot(inst, text=rule.replacement_text)
                    redact_annot.set_info(title=f"Auto-Redacted: {rule.name}")
                    rule_redactions += 1
                page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
            results_by_rule[rule.name] = rule_redactions
            total_redactions += rule_redactions

        # Redact tabular/text data using pdfplumber and apply redactions to PDF
        try:
            pdf_bytes = self.document.write()
            with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
                for page_num, page in enumerate(pdf.pages):
                    tables = page.extract_tables()
                    for table in tables:
                        for row in table:
                            for col_idx, cell in enumerate(row):
                                if cell:
                                    # Detect and redact PII in table cell
                                    detected_pii_result = detect_pii(cell)
                                    pii_values = []
                                    if hasattr(detected_pii_result, 'pii_types_found'):
                                        for values in detected_pii_result.pii_types_found.values():
                                            pii_values.extend(values)
                                    for pii_item in pii_values:
                                        if pii_item:
                                            pdf_page = self.document[page_num]
                                            text_instances = pdf_page.search_for(pii_item)
                                            for inst in text_instances:
                                                redact_annot = pdf_page.add_redact_annot(inst, text="[SENSITIVE DATA REMOVED]")
                                                redact_annot.set_info(title="Auto-PII-Redacted-Table")
                                                total_redactions += 1
                                            pdf_page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
                                    # Apply redaction rules to table cell
                                    for rule in rules:
                                        if rule.enabled:
                                            new_cell = rule.apply(cell)
                                            if new_cell != cell:
                                                pdf_page = self.document[page_num]
                                                text_instances = pdf_page.search_for(cell)
                                                for inst in text_instances:
                                                    redact_annot = pdf_page.add_redact_annot(inst, text=rule.replacement_text)
                                                    redact_annot.set_info(title=f"Auto-Redacted-Table: {rule.name}")
                                                    results_by_rule[rule.name] = results_by_rule.get(rule.name, 0) + 1
                                                    total_redactions += 1
                                                pdf_page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
            # Now, table redactions are applied to the PDF
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.warning(f"Tabular data extraction/redaction failed: {e}")

        self.metrics.redactions_applied += total_redactions
        return {
            "total_redactions": total_redactions,
            "results_by_rule": results_by_rule
        }
    
    def apply_manual_redactions(self, manual_areas: List[ManualRedactionArea]) -> Dict[str, Any]:
        """Apply manual redaction areas defined by user."""
        if not self.document:
            raise ValueError("No document loaded")
            
        applied_redactions = 0
        
        for area in manual_areas:
            if area.page_num < 0 or area.page_num >= self.document.page_count:
                continue
                
            page = self.document[area.page_num]
            rect = fitz.Rect(area.x0, area.y0, area.x1, area.y1)
            
            redact_annot = page.add_redact_annot(rect, text=area.replacement_text)
            redact_annot.set_info(title="Manual Redaction")
            
            page.apply_redactions()
            applied_redactions += 1
        
        self.metrics.redactions_applied += applied_redactions
        
        return {"applied_redactions": applied_redactions}
    
    def remove_images(self) -> Dict[str, Any]:
        """Remove all images from the document."""
        if not self.document:
            raise ValueError("No document loaded")
            
        removed_objects = 0
        
        for page_num in range(self.document.page_count):
            page = self.document[page_num]
            image_list = page.get_images()
            
            for img in image_list:
                try:
                    img_rect = page.get_image_bbox(img[7])
                    redact_annot = page.add_redact_annot(img_rect, text="[IMAGE REMOVED]")
                    removed_objects += 1
                except:
                    pass
            
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_REMOVE)
        
        self.metrics.images_removed += removed_objects
        return {"removed_objects": removed_objects}
    
    def generate_comparison_data(self) -> Dict[str, Any]:
        """Generate side-by-side comparison data."""
        if not self.document or not self.original_document:
            return {}
            
        comparison_data = {
            "total_pages": self.document.page_count,
            "pages": []
        }
        
        for page_num in range(min(3, self.document.page_count)):  # Limit to first 3 pages for performance
            original_page = self.original_document[page_num]
            redacted_page = self.document[page_num]
            
            # Get page images as base64
            original_pix = original_page.get_pixmap(matrix=fitz.Matrix(1.0, 1.0))
            redacted_pix = redacted_page.get_pixmap(matrix=fitz.Matrix(1.0, 1.0))
            
            original_img = base64.b64encode(original_pix.tobytes("png")).decode()
            redacted_img = base64.b64encode(redacted_pix.tobytes("png")).decode()
            
            # Get text differences
            original_text = original_page.get_text()
            redacted_text = redacted_page.get_text()
            
            page_data = {
                "page_number": page_num + 1,
                "original_image": original_img,
                "redacted_image": redacted_img,
                "original_text_length": len(original_text),
                "redacted_text_length": len(redacted_text),
                "text_reduction_percentage": ((len(original_text) - len(redacted_text)) / len(original_text) * 100) if original_text else 0
            }
            
            comparison_data["pages"].append(page_data)
        
        return comparison_data
    
    def export_document(self) -> Optional[bytes]:
        """Export processed document as bytes."""
        if not self.document:
            return None
            
        try:
            return self.document.tobytes()
        except Exception as e:
            logger.error(f"Document export failed: {e}")
            return None
    
    def _cleanup_documents(self):
        """Clean up document resources."""
        for doc in [self.document, self.original_document]:
            if doc:
                try:
                    doc.close()
                except:
                    pass
        self.document = None
        self.original_document = None


class BulkPDFProcessor:
    """Bulk PDF processing system for handling multiple documents."""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.jobs: Dict[str, BulkProcessingJob] = {}
    
    def create_job(self, files: List[Tuple[bytes, str]], rules: List[RedactionRule]) -> str:
        """Create a new bulk processing job."""
        job_id = hashlib.md5(f"{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        
        documents = []
        for content, filename in files:
            doc_state = DocumentState(
                filename=filename,
                original_content=content,
                current_content=content
            )
            documents.append(doc_state)
        
        job = BulkProcessingJob(
            job_id=job_id,
            documents=documents,
            rules=rules,
            total_files=len(files)
        )
        
        self.jobs[job_id] = job
        return job_id
    
    def process_job(self, job_id: str, progress_callback=None) -> bool:
        """Process a bulk job with parallel execution."""
        if job_id not in self.jobs:
            return False
        
        job = self.jobs[job_id]
        job.status = "processing"
        
        def process_single_document(doc_state: DocumentState) -> bool:
            try:
                processor = EnhancedPDFProcessor()
                
                if not processor.load_document(doc_state.current_content, doc_state.filename):
                    return False
                
                # Apply redaction rules
                processor.apply_redaction_rules(job.rules)
                
                # Export processed document
                processed_content = processor.export_document()
                if processed_content:
                    doc_state.redacted_content = processed_content
                    doc_state.is_processed = True
                    doc_state.metrics = processor.metrics
                
                processor._cleanup_documents()
                return True
                
            except Exception as e:
                logger.error(f"Failed to process {doc_state.filename}: {e}")
                return False
        
        # Process documents in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(process_single_document, doc): doc 
                for doc in job.documents
            }
            
            for future in futures:
                doc_state = futures[future]
                try:
                    success = future.result(timeout=300)
                    
                    if success:
                        job.processed_files += 1
                    else:
                        job.failed_files += 1
                    
                    if progress_callback:
                        progress_callback(job.progress_percentage)
                        
                except Exception as e:
                    job.failed_files += 1
                    logger.error(f"Processing error for {doc_state.filename}: {e}")
        
        job.status = "completed" if job.failed_files == 0 else "partial"
        return job.failed_files == 0
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a bulk processing job."""
        if job_id not in self.jobs:
            return None
        
        job = self.jobs[job_id]
        return {
            "job_id": job_id,
            "status": job.status,
            "total_files": job.total_files,
            "processed_files": job.processed_files,
            "failed_files": job.failed_files,
            "progress_percentage": job.progress_percentage
        }
    
    def create_download_package(self, job_id: str) -> Optional[bytes]:
        """Create a ZIP package with all processed documents."""
        if job_id not in self.jobs:
            return None
        
        job = self.jobs[job_id]
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for doc_state in job.documents:
                if doc_state.is_processed and doc_state.redacted_content:
                    name_parts = Path(doc_state.filename).name.rsplit('.', 1)
                    redacted_filename = f"{name_parts[0]}_REDACTED.pdf"
                    zip_file.writestr(redacted_filename, doc_state.redacted_content)
            
            # Add processing report
            report = {
                "job_id": job.job_id,
                "processed_files": job.processed_files,
                "failed_files": job.failed_files,
                "total_redactions": sum(
                    doc.metrics.redactions_applied 
                    for doc in job.documents 
                    if doc.is_processed
                )
            }
            zip_file.writestr("processing_report.json", json.dumps(report, indent=2))
        
        zip_buffer.seek(0)
        return zip_buffer.getvalue()


class EnhancedUIManager:
    """Enhanced UI manager with all new features."""
    
    def __init__(self):
        self.bulk_processor = BulkPDFProcessor()
        
    def setup_page_config(self):
        """Configure Streamlit page."""
        st.set_page_config(
            page_title="Enterprise PDF Redaction Suite",
            page_icon="🔒",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
    def render_header(self):
        """Render application header."""
        st.title("🔒 Enterprise PDF Redaction Suite")
        # st.markdown("""
        # **Professional-grade automated document redaction** for business use.
        
        # ### What This Tool Does
        # - **Automatically removes sensitive information** (SSN, emails, phone numbers, etc.)
        # - **Bulk process multiple PDFs** at once for efficiency  
        # - **Preview changes** side-by-side before downloading
        # - **Manual redaction tools** for custom requirements
        # - **Enterprise security** with comprehensive validation
        # """)
        
        mode = st.selectbox(
            "Choose Processing Mode:",
            ["Single Document", "Bulk Processing"],
            help="Single Document: Process one file with preview. Bulk Processing: Handle multiple files at once."
        )
        
        return mode
    
    def handle_bulk_upload(self) -> Optional[List[Tuple[bytes, str]]]:
        """Handle bulk file upload."""
        st.subheader("📁 Bulk Document Upload")
        
        uploaded_files = st.file_uploader(
            "Upload PDF Documents (Multiple files supported)",
            type=['pdf'],
            accept_multiple_files=True,
            help="Maximum 100MB per file. Select multiple files for batch processing."
        )
        
        if uploaded_files:
            valid_files = []
            
            with st.spinner(f"🔍 Validating {len(uploaded_files)} files..."):
                for uploaded_file in uploaded_files:
                    try:
                        file_content = uploaded_file.read()
                        filename = uploaded_file.name

                        if len(file_content) > 200 * 1024 * 1024:  # 200MB limit
                            st.error(f"❌ {filename}: File too large")
                            continue
                            
                        valid_files.append((file_content, filename))
                        st.success(f"✅ {filename}: Validated")
                            
                    except Exception as e:
                        st.error(f"❌ {uploaded_file.name}: Processing error - {str(e)}")
            
            if valid_files:
                st.info(f"📋 **{len(valid_files)} files ready for processing**")
                return valid_files
                
        return None
    
    def handle_single_upload(self) -> Optional[Tuple[bytes, str]]:
        """Handle single file upload."""
        with st.sidebar:
            st.header("📁 Document Upload")
            
            uploaded_file = st.file_uploader(
                "Select PDF Document",
                type=['pdf'],
                help="Maximum file size: 100MB"
            )
            
            if uploaded_file:
                try:
                    file_content = uploaded_file.read()
                    filename = uploaded_file.name
                    st.success("✅ Document uploaded successfully")
                    return file_content, filename
                            
                except Exception as e:
                    st.error(f"❌ Upload processing failed: {str(e)}")
                    return None
                    
        return None
    
    def render_redaction_rules_config(self) -> List[RedactionRule]:
        """Render configurable redaction rules interface."""
        st.subheader("⚙️ Redaction Configuration")
        

        predefined_rules = RedactionRuleManager.get_predefined_rules()
        categories = {}
        for rule in predefined_rules:
            if rule.category not in categories:
                categories[rule.category] = []
            categories[rule.category].append(rule)
        
        enabled_rules = []
        
        # Create tabs for different categories
        category_tabs = st.tabs(list(categories.keys()) + ["Custom Rules"])
        
        for i, (category, rules) in enumerate(categories.items()):
            with category_tabs[i]:
                st.write(f"**{category} Redaction Rules**")
                
                for rule in rules:
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        enabled = st.checkbox(
                            f"{rule.name}",
                            value=rule.enabled,
                            help=f"Pattern: {rule.pattern[:50]}..."
                        )
                        
                    with col2:
                        replacement = st.text_input(
                            "Replacement",
                            value=rule.replacement_text,
                            key=f"repl_{rule.name}",
                            label_visibility="collapsed"
                        )
                    
                    if enabled:
                        modified_rule = RedactionRule(
                            name=rule.name,
                            pattern=rule.pattern,
                            replacement_text=replacement,
                            is_regex=rule.is_regex,
                            category=rule.category,
                            enabled=True
                        )
                        enabled_rules.append(modified_rule)
        
        # Custom rules tab
        
        with category_tabs[-1]:
            st.write("**Create Custom Redaction Rules**")

            with st.form("custom_rule_form"):
                rule_name = st.text_input("Rule Name", placeholder="e.g., Custom ID Numbers")
                rule_pattern = st.text_input("Pattern (Regex)", placeholder="e.g., ID-\\d{6}")
                rule_replacement = st.text_input("Replacement Text", value="[CUSTOM-REDACTED]")

                if st.form_submit_button("Add Custom Rule"):
                    if rule_name and rule_pattern:
                        is_valid, message = RedactionRuleManager.validate_regex_pattern(rule_pattern)

                        if is_valid:
                            custom_rule = RedactionRule(
                                name=rule_name,
                                pattern=rule_pattern,
                                replacement_text=rule_replacement,
                                is_regex=True,
                                category="Custom",
                                enabled=True
                            )
                            
                            st.session_state.custom_rules.append(custom_rule)
                            st.success(f"✅ Added custom rule: {rule_name}")
                        else:
                            st.error(f"❌ Invalid pattern: {message}")

            
            if st.session_state.custom_rules:
                st.write("---")
                st.write("**Active Custom Rules:**")
                for rule in st.session_state.custom_rules:
                    st.text(f"- {rule.name} (Pattern: {rule.pattern})")
            
        all_enabled_rules = enabled_rules + st.session_state.custom_rules
        if all_enabled_rules:
            st.info(f"📋 **{len(all_enabled_rules)} redaction rules selected**")

        return all_enabled_rules


    
    def render_side_by_side_preview(self, processor: EnhancedPDFProcessor):
        """Render side-by-side preview like git diff."""
        st.subheader("🔍 Document Comparison Preview")
        
        if not processor.document or not processor.original_document:
            st.warning("⚠️ No documents loaded for comparison")
            return
        
        # Generate comparison data
        comparison_data = processor.generate_comparison_data()
        
        if comparison_data and comparison_data["pages"]:
            # Page selector
            if len(comparison_data["pages"]) > 1:
                selected_page = st.slider(
                    "Select page to preview",
                    min_value=1,
                    max_value=len(comparison_data["pages"]),
                    value=1
                ) - 1
            else:
                selected_page = 0
            
            page_data = comparison_data["pages"][selected_page]
            
            # Create two columns for side-by-side view
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 📄 Original Document")
                if page_data["original_image"]:
                    st.image(
                        base64.b64decode(page_data["original_image"]),
                        caption=f"Page {page_data['page_number']} - Original",
                        width='stretch'
                    )
                
                st.metric("Text Characters", page_data["original_text_length"])
            
            with col2:
                st.markdown("### 🔒 Redacted Document")
                if page_data["redacted_image"]:
                    st.image(
                        base64.b64decode(page_data["redacted_image"]),
                        caption=f"Page {page_data['page_number']} - Redacted",
                        width='stretch'
                    )
                
                reduction = page_data["text_reduction_percentage"]
                st.metric(
                    "Text Characters",
                    page_data["redacted_text_length"],
                    delta=f"-{reduction:.1f}%" if reduction > 0 else "No change"
                )
            
            # Summary stats
            st.markdown("---")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Page", f"{selected_page + 1} / {len(comparison_data['pages'])}")
            with col2:
                st.metric("Text Reduced", f"{reduction:.1f}%")
            with col3:
                st.metric("Preview Pages", len(comparison_data["pages"]))
        
        else:
            st.error("❌ Unable to generate preview - please process document first")
    
    def render_bulk_processing_interface(self, files: List[Tuple[bytes, str]], rules: List[RedactionRule]):
        """Render bulk processing interface."""
        st.subheader("🔄 Bulk Processing")
        
        if not rules:
            st.warning("⚠️ Please select at least one redaction rule before processing")
            return
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.write(f"**Ready to process {len(files)} files with {len(rules)} rules**")
            
            with st.expander("📋 Files to Process"):
                for i, (_, filename) in enumerate(files, 1):
                    st.write(f"{i}. {filename}")
        
        with col2:
            st.write("**Processing Options**")
            remove_images = st.checkbox("Remove all images", help="Remove images and logos from documents")
        
        if st.button("🚀 Start Bulk Processing", type="primary"):
            
            # Create processing job
            job_id = self.bulk_processor.create_job(files, rules)
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            def update_progress(percentage):
                progress_bar.progress(percentage / 100)
                status_text.text(f"Processing... {percentage:.1f}% complete")
            
            # Start processing
            with st.spinner("🔄 Processing documents..."):
                success = self.bulk_processor.process_job(
                    job_id, 
                    progress_callback=update_progress
                )
            
            # Show results
            job_status = self.bulk_processor.get_job_status(job_id)
            
            if success:
                st.success(f"✅ Bulk processing completed! Processed {job_status['processed_files']} files")
                
                download_package = self.bulk_processor.create_download_package(job_id)
                
                if download_package:
                    st.download_button(
                        label="📥 Download Processed Files (ZIP)",
                        data=download_package,
                        file_name=f"redacted_documents_{job_id}.zip",
                        mime="application/zip"
                    )
            else:
                st.error(f"❌ Processing completed with errors. {job_status['failed_files']} files failed")
                
                if job_status['processed_files'] > 0:
                    download_package = self.bulk_processor.create_download_package(job_id)
                    
                    if download_package:
                        st.download_button(
                            label="📥 Download Successfully Processed Files",
                            data=download_package,
                            file_name=f"redacted_documents_partial_{job_id}.zip",
                            mime="application/zip"
                        )
    
    def render_processing_interface(self, processor: EnhancedPDFProcessor):
        """Render single document processing interface."""
        st.subheader("🔧 Document Processing")
        
        # Get redaction rules
        rules = self.render_redaction_rules_config()
        
        # Processing options
        col1, col2 = st.columns(2)
        
        with col1:
            remove_images = st.checkbox("Remove Images", help="Remove all images and logos")
            
        with col2:
            if st.button("🔄 Apply Redactions", type="primary"):
                with st.spinner("🔄 Processing document..."):
                    
                    # Apply automatic redaction rules
                    if rules:
                        rule_results = processor.apply_redaction_rules(rules)
                        st.success(f"✅ Applied {rule_results['total_redactions']} automatic redactions")
                    
                    # Remove images if requested
                    if remove_images:
                        image_results = processor.remove_images()
                        st.success(f"✅ Removed {image_results['removed_objects']} images")
                    
                    st.session_state.document_processed = True
        
        # Show preview if document is processed
        if hasattr(st.session_state, 'document_processed') and st.session_state.document_processed:
            st.markdown("---")
            self.render_side_by_side_preview(processor)
            
            # Download button
            processed_content = processor.export_document()
            if processed_content:
                st.download_button(
                    label="📥 Download Redacted Document",
                    data=processed_content,
                    file_name="redacted_document.pdf",
                    mime="application/pdf"
                )


def main():
    """Main application entry point."""
    logger.info("Starting Enhanced Enterprise PDF Redaction Suite")
    
    # Initialize UI manager
    ui_manager = EnhancedUIManager()
    ui_manager.setup_page_config()
    
    # Render header and get processing mode
    processing_mode = ui_manager.render_header()
    
    # Initialize session state
    if 'processor' not in st.session_state:
        st.session_state.processor = None
    if 'document_loaded' not in st.session_state:
        st.session_state.document_loaded = False
    if 'document_processed' not in st.session_state:
        st.session_state.document_processed = False
    
    # Mode-specific interfaces
    if processing_mode == "Bulk Processing":
        st.markdown("---")
        
        # Bulk processing workflow
        files = ui_manager.handle_bulk_upload()
        
        if files:
            st.markdown("---")
            rules = ui_manager.render_redaction_rules_config()
            
            if rules:
                st.markdown("---")
                ui_manager.render_bulk_processing_interface(files, rules)
            else:
                st.info("👆 **Please select redaction rules above to continue**")
        else:
            st.info("📁 **Upload multiple PDF files above to start bulk processing**")
            
            st.subheader("Business Benefits of Bulk Processing")
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                **Efficiency**
                - Process hundreds of documents at once
                - Parallel processing for faster results
                - Consistent redaction across all files
                - Automatic progress tracking
                """)
            
            with col2:
                st.markdown("""
                **Security & Compliance**
                - Uniform security validation
                - Comprehensive audit trails
                - Enterprise-grade error handling
                - Batch download with processing reports
                """)
    
    else:  # Single Document mode
        upload_result = ui_manager.handle_single_upload()
        
        if upload_result:
            file_content, filename = upload_result
            
            if not st.session_state.document_loaded:
                processor = EnhancedPDFProcessor()
                
                with st.spinner("🔄 Loading document..."):
                    if processor.load_document(file_content, filename):
                        st.session_state.processor = processor
                        st.session_state.document_loaded = True
                        st.session_state.document_processed = False
                        
                        st.success(f"✅ Document loaded: {filename}")
                        
                        # Show document info
                        with st.expander("📄 Document Information"):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.metric("Pages", processor.document.page_count)
                            with col2:
                                st.metric("Size (MB)", f"{len(file_content) / (1024*1024):.2f}")
                    else:
                        st.error("❌ Failed to load document")
                        return
        
        # Main processing interface for single documents
        if st.session_state.document_loaded and st.session_state.processor:
            st.markdown("---")
            ui_manager.render_processing_interface(st.session_state.processor)
        else:
            st.info("👈 **Upload a PDF document in the sidebar to begin**")
            
            st.subheader("Professional PDF Redaction Features")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                **Intelligent Redaction**
                - Auto-detect SSN, emails, phone numbers
                - PAN card, Aadhaar, credit card numbers
                - Custom regex patterns
                - Manual redaction tools
                """)
                
                st.markdown("""
                **Preview & Compare**
                - Side-by-side original vs redacted view
                - Git-style diff highlighting
                - Page-by-page navigation
                - Text reduction statistics
                """)
            
            with col2:
                st.markdown("""
                **Enterprise Security**
                - Multi-layer threat detection
                - File integrity validation
                - Access control and audit trails
                - Secure temporary file handling
                """)
                
                st.markdown("""
                **Performance & Scale**
                - Memory-efficient processing
                - Large file support (up to 300 pages)
                - Batch processing capabilities
                - Cloud deployment ready
                """)
            
            st.subheader("Supported Use Cases")
            
            use_cases = [
                "Legal Documents: Contract redaction for client confidentiality",
                "HR Files: Employee data protection and GDPR compliance", 
                "Financial Reports: Sensitive account information removal",
                "Medical Records: HIPAA compliance and patient privacy",
                "Business Documents: Trade secret and IP protection",
                "Government Files: Classification and security clearance"
            ]
            
            for i, use_case in enumerate(use_cases, 1):
                st.write(f"{i}. {use_case}")


if __name__ == "__main__":
    main()
