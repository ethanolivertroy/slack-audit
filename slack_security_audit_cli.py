#!/usr/bin/env python3
"""
Slack Security Audit Tool CLI

A comprehensive security assessment tool for Slack workspaces that evaluates
compliance with industry standards, FedRAMP requirements, and NIST 800-53 controls.
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from slack_security_audit import SecurityAuditPlatform, AuditConfig
from slack_security_audit.exceptions import SlackAuditException


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_arguments() -> argparse.ArgumentParser:
    """Set up command line arguments."""
    parser = argparse.ArgumentParser(
        description="Slack Security Audit Tool - Comprehensive security assessment for Slack workspaces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run a basic audit with default settings
  %(prog)s --token xoxb-your-token

  # Run audit with specific frameworks
  %(prog)s --token xoxb-your-token --frameworks nist_800_53 cis

  # Use a configuration file
  %(prog)s --token xoxb-your-token --config config.yaml

  # Run audit with custom output directory
  %(prog)s --token xoxb-your-token --output ./my-audit-results

  # Enable verbose logging
  %(prog)s --token xoxb-your-token --verbose
        """
    )
    
    # Required arguments
    parser.add_argument(
        "--token",
        required=True,
        help="Slack API token with admin privileges (or set SLACK_AUDIT_TOKEN env var)",
        default=None
    )
    
    # Optional arguments
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file (YAML or JSON)"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default="./audit_results",
        help="Directory to store audit results (default: ./audit_results)"
    )
    
    parser.add_argument(
        "--frameworks",
        nargs="+",
        choices=["nist_800_53", "fedramp", "cis", "iso_27001", "all"],
        help="Compliance frameworks to assess (default: all)"
    )
    
    parser.add_argument(
        "--mode",
        choices=["point_in_time", "continuous"],
        default="point_in_time",
        help="Audit mode (default: point_in_time)"
    )
    
    parser.add_argument(
        "--formats",
        nargs="+",
        choices=["json", "html", "markdown", "csv"],
        default=["json", "html", "markdown"],
        help="Report output formats (default: json, html, markdown)"
    )
    
    parser.add_argument(
        "--cia-weights",
        nargs=3,
        type=float,
        metavar=("C", "I", "A"),
        help="CIA triad weights for risk scoring (must sum to 1.0)"
    )
    
    parser.add_argument(
        "--no-deep-scan",
        action="store_true",
        help="Disable deep scanning for faster execution"
    )
    
    parser.add_argument(
        "--include-evidence",
        action="store_true",
        default=True,
        help="Include evidence in reports (default: True)"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0"
    )
    
    return parser


def build_config(args: argparse.Namespace) -> AuditConfig:
    """Build audit configuration from command line arguments."""
    # Start with default config or load from file
    if args.config:
        logger.info(f"Loading configuration from {args.config}")
        config = AuditConfig.from_file(args.config)
    else:
        config = AuditConfig.default_audit_config()
    
    # Override with command line arguments
    if args.mode:
        config.mode = args.mode
    
    if args.frameworks and "all" not in args.frameworks:
        # Filter frameworks based on command line
        config.frameworks = [
            f for f in config.frameworks 
            if f.name in args.frameworks
        ]
    
    if args.formats:
        config.reporting.formats = args.formats
    
    if args.cia_weights:
        c, i, a = args.cia_weights
        if abs(sum([c, i, a]) - 1.0) > 0.001:
            raise ValueError("CIA weights must sum to 1.0")
        config.cia_weights.confidentiality = c
        config.cia_weights.integrity = i
        config.cia_weights.availability = a
    
    if args.no_deep_scan:
        config.scanning.deep_scan = False
    
    config.reporting.include_evidence = args.include_evidence
    
    return config


async def run_audit(token: str, config: AuditConfig, output_dir: str) -> None:
    """Run the security audit."""
    logger.info("Initializing Slack Security Audit Platform...")
    
    try:
        # Initialize the platform
        platform = SecurityAuditPlatform(
            token=token,
            config=config,
            output_dir=output_dir
        )
        
        # Use the client context manager
        async with platform.client:
            logger.info("Starting security audit...")
            
            # Run the audit
            if config.mode == "point_in_time":
                result = await platform.run_audit()
                
                # Display summary
                print("\n" + "="*60)
                print("SLACK SECURITY AUDIT SUMMARY")
                print("="*60)
                print(f"Audit ID: {result.audit_id}")
                print(f"Workspace: {result.workspace_info.get('team_name', 'Unknown')}")
                print(f"Started: {result.started_at}")
                print(f"Completed: {result.completed_at}")
                print()
                
                # Display compliance summary
                print("COMPLIANCE SUMMARY:")
                for framework, summary in result.compliance_summary.items():
                    print(f"\n{framework.upper()}:")
                    print(f"  Total Controls: {summary['total_controls']}")
                    print(f"  Compliant: {summary['compliant']}")
                    print(f"  Non-Compliant: {summary['non_compliant']}")
                    print(f"  Partially Compliant: {summary['partially_compliant']}")
                    print(f"  Compliance Rate: {summary['compliance_percentage']:.1f}%")
                
                # Display risk summary
                print("\nRISK SUMMARY:")
                risk = result.risk_summary
                print(f"  Total Findings: {risk['total_findings']}")
                print(f"  Critical: {risk['by_severity']['critical']}")
                print(f"  High: {risk['by_severity']['high']}")
                print(f"  Medium: {risk['by_severity']['medium']}")
                print(f"  Low: {risk['by_severity']['low']}")
                print(f"  Average Risk Score: {risk['average_risk_score']:.2f}/10")
                
                # Display top recommendations
                if result.recommendations:
                    print("\nTOP RECOMMENDATIONS:")
                    for i, rec in enumerate(result.recommendations[:5], 1):
                        print(f"\n{i}. {rec['title']} (Risk Score: {rec['risk_score']:.1f})")
                        for action in rec['recommendations'][:2]:
                            if action:
                                print(f"   - {action}")
                
                print(f"\nFull reports saved to: {output_dir}")
                print("="*60)
                
            else:
                # Continuous monitoring not implemented yet
                raise NotImplementedError("Continuous monitoring mode is not yet implemented")
            
    except SlackAuditException as e:
        logger.error(f"Audit failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    # Parse arguments
    parser = setup_arguments()
    args = parser.parse_args()
    
    # Set up logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get token (from argument or environment)
    token = args.token
    if not token:
        import os
        token = os.getenv("SLACK_AUDIT_TOKEN")
        if not token:
            parser.error("--token is required or set SLACK_AUDIT_TOKEN environment variable")
    
    try:
        # Build configuration
        config = build_config(args)
        
        # Run the audit
        asyncio.run(run_audit(token, config, args.output))
        
    except ValueError as e:
        parser.error(str(e))
    except KeyboardInterrupt:
        logger.info("Audit interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()