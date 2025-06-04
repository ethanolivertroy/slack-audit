"""
Core platform for the Slack Security Audit tool.
"""

import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Type
import logging

from .config import AuditConfig
from .models import AuditResult, ControlResult, Finding, Severity, ComplianceStatus
from .exceptions import SlackAuditException, FrameworkNotFoundError
from .slack_client import SlackClient
from .frameworks.base import ComplianceFramework
from .analyzers.cia_analyzer import CIAImpactAnalyzer
from .analyzers.risk_scorer import RiskScorer
from .collectors.base import DataCollector
from .reporters.base import Reporter


logger = logging.getLogger(__name__)


class SecurityAuditPlatform:
    """Main orchestrator for comprehensive security audits."""
    
    def __init__(
        self,
        token: str,
        config: Optional[AuditConfig] = None,
        output_dir: str = "./audit_results"
    ):
        """
        Initialize the Security Audit Platform.
        
        Args:
            token: Slack API token with admin privileges
            config: Audit configuration (uses default if not provided)
            output_dir: Directory to store audit results
        """
        self.token = token
        self.config = config or AuditConfig.default_audit_config()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.client = SlackClient(token, self.config.scanning)
        self.cia_analyzer = CIAImpactAnalyzer(self.config.cia_weights)
        self.risk_scorer = RiskScorer(self.config)
        
        # Framework registry
        self._frameworks: Dict[str, Type[ComplianceFramework]] = {}
        self._load_frameworks()
        
        # Data collectors
        self._collectors: List[DataCollector] = []
        self._load_collectors()
        
        # Reporters
        self._reporters: List[Reporter] = []
        self._load_reporters()
        
        # Current audit result
        self.current_audit: Optional[AuditResult] = None
    
    def _load_frameworks(self):
        """Load compliance framework plugins."""
        # Import framework implementations
        from .frameworks.nist_800_53 import NIST80053Framework
        from .frameworks.fedramp import FedRAMPFramework
        from .frameworks.cis import CISFramework
        from .frameworks.iso_27001 import ISO27001Framework
        
        # Register frameworks
        self.register_framework("nist_800_53", NIST80053Framework)
        self.register_framework("fedramp", FedRAMPFramework)
        self.register_framework("cis", CISFramework)
        self.register_framework("iso_27001", ISO27001Framework)
    
    def _load_collectors(self):
        """Load data collector plugins."""
        from .collectors.enterprise_collector import EnterpriseCollector
        from .collectors.workspace_collector import WorkspaceCollector
        from .collectors.user_collector import UserCollector
        from .collectors.app_collector import AppCollector
        from .collectors.file_collector import FileCollector
        from .collectors.audit_log_collector import AuditLogCollector
        
        self._collectors = [
            EnterpriseCollector(self.client),
            WorkspaceCollector(self.client),
            UserCollector(self.client),
            AppCollector(self.client),
            FileCollector(self.client),
            AuditLogCollector(self.client),
        ]
    
    def _load_reporters(self):
        """Load report generators."""
        from .reporters.json_reporter import JSONReporter
        from .reporters.html_reporter import HTMLReporter
        from .reporters.markdown_reporter import MarkdownReporter
        from .reporters.csv_reporter import CSVReporter
        
        reporter_map = {
            "json": JSONReporter,
            "html": HTMLReporter,
            "markdown": MarkdownReporter,
            "csv": CSVReporter,
        }
        
        for format_name in self.config.reporting.formats:
            if format_name in reporter_map:
                self._reporters.append(reporter_map[format_name](self.config))
    
    def register_framework(self, name: str, framework_class: Type[ComplianceFramework]):
        """Register a compliance framework."""
        self._frameworks[name] = framework_class
    
    async def run_audit(self) -> AuditResult:
        """
        Run a comprehensive security audit.
        
        Returns:
            AuditResult containing all findings and compliance status
        """
        audit_id = str(uuid.uuid4())
        logger.info(f"Starting security audit {audit_id}")
        
        # Initialize audit result
        self.current_audit = AuditResult(
            audit_id=audit_id,
            audit_type=self.config.mode,
            started_at=datetime.now(),
            metadata={
                "tool_version": "2.0.0",
                "config": self.config.__dict__
            }
        )
        
        try:
            # Validate token and get workspace info
            workspace_info = await self.client.validate_token()
            self.current_audit.workspace_info = workspace_info
            
            # Collect data from Slack
            logger.info("Collecting data from Slack APIs...")
            await self._collect_data()
            
            # Run compliance assessments
            logger.info("Running compliance assessments...")
            await self._run_compliance_assessments()
            
            # Analyze findings and calculate risk scores
            logger.info("Analyzing findings and calculating risk scores...")
            self._analyze_findings()
            
            # Generate compliance and risk summaries
            self._generate_summaries()
            
            # Mark audit as complete
            self.current_audit.completed_at = datetime.now()
            
            # Generate reports
            logger.info("Generating reports...")
            await self._generate_reports()
            
            logger.info(f"Audit {audit_id} completed successfully")
            return self.current_audit
            
        except Exception as e:
            logger.error(f"Audit failed: {str(e)}")
            self.current_audit.metadata["error"] = str(e)
            self.current_audit.completed_at = datetime.now()
            raise
    
    async def _collect_data(self):
        """Collect data from all registered collectors."""
        tasks = []
        for collector in self._collectors:
            if collector.is_applicable(self.current_audit.workspace_info):
                tasks.append(collector.collect())
        
        # Run collectors in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Merge results into raw_data
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Collector {self._collectors[i].__class__.__name__} failed: {result}")
                continue
            
            collector_name = self._collectors[i].name
            self.current_audit.raw_data[collector_name] = result
    
    async def _run_compliance_assessments(self):
        """Run assessments for all configured frameworks."""
        for framework_config in self.config.frameworks:
            if not framework_config.enabled:
                continue
            
            framework_name = framework_config.name
            if framework_name not in self._frameworks:
                logger.warning(f"Framework {framework_name} not found")
                continue
            
            logger.info(f"Assessing {framework_name} compliance...")
            
            # Initialize framework
            framework_class = self._frameworks[framework_name]
            framework = framework_class(
                config=framework_config,
                cia_analyzer=self.cia_analyzer,
                risk_scorer=self.risk_scorer
            )
            
            # Run assessment
            try:
                control_results = await framework.assess(
                    self.current_audit.raw_data,
                    self.current_audit.workspace_info
                )
                
                # Add results to audit
                for result in control_results:
                    self.current_audit.add_control_result(framework_name, result)
                    
                    # Extract findings
                    self.current_audit.findings.extend(result.findings)
                    
            except Exception as e:
                logger.error(f"Framework {framework_name} assessment failed: {e}")
                continue
    
    def _analyze_findings(self):
        """Analyze all findings and enrich with risk scores."""
        for finding in self.current_audit.findings:
            # Calculate risk score for each finding
            risk_score = self.risk_scorer.calculate_finding_risk(
                finding,
                self.current_audit.workspace_info
            )
            finding.risk_score = risk_score.final_score
            finding.risk_details = risk_score
    
    def _generate_summaries(self):
        """Generate compliance and risk summaries."""
        # Compliance summary by framework
        for framework_name in self.current_audit.control_results:
            results = self.current_audit.control_results[framework_name]
            
            summary = {
                "total_controls": len(results),
                "compliant": sum(1 for r in results if r.status == ComplianceStatus.COMPLIANT),
                "non_compliant": sum(1 for r in results if r.status == ComplianceStatus.NON_COMPLIANT),
                "partially_compliant": sum(1 for r in results if r.status == ComplianceStatus.PARTIALLY_COMPLIANT),
                "not_applicable": sum(1 for r in results if r.status == ComplianceStatus.NOT_APPLICABLE),
                "compliance_percentage": self.current_audit.calculate_compliance_percentage(framework_name)
            }
            
            self.current_audit.compliance_summary[framework_name] = summary
        
        # Risk summary
        risk_summary = {
            "total_findings": len(self.current_audit.findings),
            "by_severity": {
                "critical": len([f for f in self.current_audit.findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self.current_audit.findings if f.severity == Severity.HIGH]),
                "medium": len([f for f in self.current_audit.findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self.current_audit.findings if f.severity == Severity.LOW]),
                "info": len([f for f in self.current_audit.findings if f.severity == Severity.INFO]),
            },
            "average_risk_score": sum(f.risk_score for f in self.current_audit.findings) / len(self.current_audit.findings) if self.current_audit.findings else 0,
            "high_risk_controls": len(self.current_audit.get_high_risk_controls()),
        }
        
        self.current_audit.risk_summary = risk_summary
        
        # Generate prioritized recommendations
        self._generate_recommendations()
    
    def _generate_recommendations(self):
        """Generate prioritized recommendations based on findings."""
        # Group findings by control and severity
        recommendations = []
        
        # Get critical and high severity findings first
        critical_findings = [f for f in self.current_audit.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        
        for finding in sorted(critical_findings, key=lambda f: f.risk_score, reverse=True)[:10]:
            rec = {
                "priority": "immediate",
                "finding_id": finding.id,
                "title": finding.title,
                "impact": finding.cia_impact,
                "risk_score": finding.risk_score,
                "recommendations": finding.recommendations,
                "estimated_effort": self._estimate_remediation_effort(finding)
            }
            recommendations.append(rec)
        
        self.current_audit.recommendations = recommendations
    
    def _estimate_remediation_effort(self, finding: Finding) -> str:
        """Estimate the effort required to remediate a finding."""
        # Simple heuristic based on finding characteristics
        if "configuration" in finding.title.lower():
            return "low"
        elif "implement" in finding.title.lower() or "deploy" in finding.title.lower():
            return "high"
        else:
            return "medium"
    
    async def _generate_reports(self):
        """Generate all configured reports."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.output_dir / f"audit_{timestamp}"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        for reporter in self._reporters:
            try:
                await reporter.generate(self.current_audit, report_dir)
                logger.info(f"Generated {reporter.format} report")
            except Exception as e:
                logger.error(f"Failed to generate {reporter.format} report: {e}")
    
    async def run_continuous_monitoring(self):
        """Run continuous monitoring (not implemented in this version)."""
        raise NotImplementedError("Continuous monitoring will be implemented in a future version")