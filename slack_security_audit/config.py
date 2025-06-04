"""
Configuration management for the Slack Security Audit Platform.
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class CIAWeights:
    """Weights for CIA triad impact scoring."""
    confidentiality: float = 0.4
    integrity: float = 0.3
    availability: float = 0.3
    
    def __post_init__(self):
        total = self.confidentiality + self.integrity + self.availability
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"CIA weights must sum to 1.0, got {total}")


@dataclass
class ScanningConfig:
    """Configuration for scanning options."""
    deep_scan: bool = True
    scan_messages: bool = False  # Privacy consideration
    scan_files: bool = True
    scan_private_channels: bool = False
    parallel_requests: int = 10
    request_timeout: int = 30
    rate_limit_delay: float = 0.5


@dataclass
class ReportingConfig:
    """Configuration for report generation."""
    formats: List[str] = field(default_factory=lambda: ["json", "html", "markdown"])
    include_evidence: bool = True
    include_raw_data: bool = False
    executive_summary: bool = True
    technical_details: bool = True
    remediation_guidance: bool = True
    risk_matrix: bool = True


@dataclass
class FrameworkConfig:
    """Configuration for a compliance framework."""
    name: str
    enabled: bool = True
    version: Optional[str] = None
    profile: Optional[str] = None
    custom_controls: List[str] = field(default_factory=list)
    excluded_controls: List[str] = field(default_factory=list)


@dataclass
class AuditConfig:
    """Main configuration for the audit platform."""
    mode: str = "point_in_time"  # or "continuous"
    frameworks: List[FrameworkConfig] = field(default_factory=list)
    cia_weights: CIAWeights = field(default_factory=CIAWeights)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    
    # Risk scoring thresholds
    risk_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "critical": 9.0,
        "high": 7.0,
        "medium": 4.0,
        "low": 2.0
    })
    
    # Advanced features
    enable_dlp: bool = False
    enable_behavioral_analytics: bool = False
    enable_threat_detection: bool = False
    
    # Integration settings
    integrations: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    @classmethod
    def from_file(cls, config_path: Path) -> "AuditConfig":
        """Load configuration from a YAML or JSON file."""
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        content = config_path.read_text()
        
        if config_path.suffix in [".yaml", ".yml"]:
            data = yaml.safe_load(content)
        elif config_path.suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported config format: {config_path.suffix}")
        
        return cls._from_dict(data)
    
    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "AuditConfig":
        """Create AuditConfig from dictionary."""
        config = cls()
        
        if "mode" in data:
            config.mode = data["mode"]
        
        if "frameworks" in data:
            config.frameworks = [
                FrameworkConfig(**f) if isinstance(f, dict) else FrameworkConfig(name=f)
                for f in data["frameworks"]
            ]
        
        if "cia_weights" in data:
            config.cia_weights = CIAWeights(**data["cia_weights"])
        
        if "scanning" in data:
            config.scanning = ScanningConfig(**data["scanning"])
        
        if "reporting" in data:
            config.reporting = ReportingConfig(**data["reporting"])
        
        if "risk_thresholds" in data:
            config.risk_thresholds = data["risk_thresholds"]
        
        if "enable_dlp" in data:
            config.enable_dlp = data["enable_dlp"]
        
        if "enable_behavioral_analytics" in data:
            config.enable_behavioral_analytics = data["enable_behavioral_analytics"]
        
        if "enable_threat_detection" in data:
            config.enable_threat_detection = data["enable_threat_detection"]
        
        if "integrations" in data:
            config.integrations = data["integrations"]
        
        return config
    
    @classmethod
    def default_audit_config(cls) -> "AuditConfig":
        """Create a default configuration for point-in-time auditing."""
        return cls(
            mode="point_in_time",
            frameworks=[
                FrameworkConfig(name="nist_800_53", version="5", profile="high"),
                FrameworkConfig(name="fedramp", profile="high"),
                FrameworkConfig(name="cis", version="1.1"),
            ],
            cia_weights=CIAWeights(
                confidentiality=0.4,
                integrity=0.3,
                availability=0.3
            ),
            scanning=ScanningConfig(
                deep_scan=True,
                scan_files=True,
                scan_messages=False
            ),
            reporting=ReportingConfig(
                formats=["json", "html", "markdown"],
                include_evidence=True,
                executive_summary=True
            )
        )