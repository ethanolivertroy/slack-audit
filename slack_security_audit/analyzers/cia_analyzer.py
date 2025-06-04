"""
CIA Triad Impact Analyzer for security findings and controls.
"""

from typing import Dict, List, Any, Optional
from ..models import CIATriad, CIAImpact, Finding, ControlResult
from ..config import CIAWeights


class CIAImpactAnalyzer:
    """Analyzes and scores CIA triad impacts for security findings."""
    
    def __init__(self, weights: CIAWeights):
        """
        Initialize the CIA analyzer.
        
        Args:
            weights: CIA weights for scoring
        """
        self.weights = weights
        
        # Control to CIA mapping database
        self._control_cia_map = self._initialize_control_mappings()
        
        # Finding pattern to CIA impact mapping
        self._pattern_cia_map = self._initialize_pattern_mappings()
    
    def _initialize_control_mappings(self) -> Dict[str, CIATriad]:
        """Initialize control ID to CIA impact mappings."""
        return {
            # Access Control family - primarily Confidentiality
            "AC-2": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.LOW),
            "AC-3": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.NONE),
            "AC-5": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            "AC-6": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            
            # Audit family - primarily Integrity
            "AU-2": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            "AU-3": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.NONE),
            "AU-4": CIATriad(confidentiality=CIAImpact.NONE, integrity=CIAImpact.MEDIUM, availability=CIAImpact.HIGH),
            "AU-6": CIATriad(confidentiality=CIAImpact.MEDIUM, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            "AU-9": CIATriad(confidentiality=CIAImpact.MEDIUM, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            
            # Configuration Management - primarily Integrity
            "CM-2": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "CM-3": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "CM-5": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            "CM-6": CIATriad(confidentiality=CIAImpact.MEDIUM, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            
            # Contingency Planning - primarily Availability
            "CP-9": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.MEDIUM, availability=CIAImpact.HIGH),
            "CP-10": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.MEDIUM, availability=CIAImpact.HIGH),
            
            # Identification and Authentication - Confidentiality and Integrity
            "IA-2": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            "IA-5": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.LOW),
            "IA-8": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            
            # Incident Response - all three
            "IR-4": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.HIGH),
            "IR-5": CIATriad(confidentiality=CIAImpact.MEDIUM, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "IR-6": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.MEDIUM),
            
            # Media Protection - primarily Confidentiality
            "MP-2": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.LOW),
            "MP-5": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.LOW, availability=CIAImpact.NONE),
            
            # System and Communications Protection - Confidentiality and Integrity
            "SC-7": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "SC-8": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            "SC-13": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.NONE),
            "SC-28": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.LOW),
            
            # System and Information Integrity - primarily Integrity
            "SI-3": CIATriad(confidentiality=CIAImpact.MEDIUM, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "SI-4": CIATriad(confidentiality=CIAImpact.MEDIUM, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "SI-7": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
        }
    
    def _initialize_pattern_mappings(self) -> Dict[str, CIATriad]:
        """Initialize finding pattern to CIA impact mappings."""
        return {
            # Authentication/Access patterns
            "authentication": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            "2fa": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            "mfa": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            "password": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.LOW),
            "access_control": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.LOW),
            "permission": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.LOW),
            
            # Data protection patterns
            "encryption": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.NONE),
            "data_loss": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.LOW, availability=CIAImpact.LOW),
            "dlp": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.LOW, availability=CIAImpact.NONE),
            "retention": CIATriad(confidentiality=CIAImpact.MEDIUM, integrity=CIAImpact.LOW, availability=CIAImpact.HIGH),
            "backup": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.MEDIUM, availability=CIAImpact.HIGH),
            
            # Audit/Logging patterns
            "audit": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "logging": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "monitoring": CIATriad(confidentiality=CIAImpact.MEDIUM, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            
            # Network/Communication patterns
            "network": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "firewall": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "vpn": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.LOW),
            "tls": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.LOW),
            
            # Malware/Threat patterns
            "malware": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.HIGH),
            "virus": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.HIGH),
            "phishing": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.MEDIUM, availability=CIAImpact.LOW),
            "threat": CIATriad(confidentiality=CIAImpact.HIGH, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            
            # Configuration patterns
            "configuration": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "baseline": CIATriad(confidentiality=CIAImpact.LOW, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
            "hardening": CIATriad(confidentiality=CIAImpact.MEDIUM, integrity=CIAImpact.HIGH, availability=CIAImpact.MEDIUM),
        }
    
    def analyze_control(self, control_id: str, control_title: str) -> CIATriad:
        """
        Analyze CIA impact for a specific control.
        
        Args:
            control_id: Control identifier (e.g., "AC-2")
            control_title: Control title for pattern matching
            
        Returns:
            CIATriad impact assessment
        """
        # First check if we have a direct mapping
        if control_id in self._control_cia_map:
            return self._control_cia_map[control_id]
        
        # Otherwise, analyze based on patterns in the title
        return self._analyze_by_patterns(control_title)
    
    def analyze_finding(self, finding: Finding) -> CIATriad:
        """
        Analyze CIA impact for a specific finding.
        
        Args:
            finding: Security finding
            
        Returns:
            CIATriad impact assessment
        """
        # Analyze based on finding title and description
        text = f"{finding.title} {finding.description}".lower()
        return self._analyze_by_patterns(text)
    
    def _analyze_by_patterns(self, text: str) -> CIATriad:
        """
        Analyze CIA impact based on text patterns.
        
        Args:
            text: Text to analyze
            
        Returns:
            CIATriad impact assessment
        """
        text_lower = text.lower()
        
        # Track impacts found
        c_impacts = []
        i_impacts = []
        a_impacts = []
        
        # Check each pattern
        for pattern, impact in self._pattern_cia_map.items():
            if pattern in text_lower:
                c_impacts.append(impact.confidentiality)
                i_impacts.append(impact.integrity)
                a_impacts.append(impact.availability)
        
        # If no patterns matched, return medium impact for all
        if not c_impacts:
            return CIATriad(
                confidentiality=CIAImpact.MEDIUM,
                integrity=CIAImpact.MEDIUM,
                availability=CIAImpact.MEDIUM
            )
        
        # Return the highest impact for each dimension
        return CIATriad(
            confidentiality=max(c_impacts, key=lambda x: self._impact_to_score(x)),
            integrity=max(i_impacts, key=lambda x: self._impact_to_score(x)),
            availability=max(a_impacts, key=lambda x: self._impact_to_score(x))
        )
    
    def _impact_to_score(self, impact: CIAImpact) -> float:
        """Convert impact enum to numeric score."""
        scores = {
            CIAImpact.HIGH: 1.0,
            CIAImpact.MEDIUM: 0.6,
            CIAImpact.LOW: 0.3,
            CIAImpact.NONE: 0.0
        }
        return scores[impact]
    
    def calculate_aggregate_impact(self, impacts: List[CIATriad]) -> CIATriad:
        """
        Calculate aggregate CIA impact from multiple impacts.
        
        Args:
            impacts: List of CIA impacts
            
        Returns:
            Aggregate CIATriad impact
        """
        if not impacts:
            return CIATriad()
        
        # Calculate average scores
        c_score = sum(self._impact_to_score(i.confidentiality) for i in impacts) / len(impacts)
        i_score = sum(self._impact_to_score(i.integrity) for i in impacts) / len(impacts)
        a_score = sum(self._impact_to_score(i.availability) for i in impacts) / len(impacts)
        
        # Convert back to impact levels
        def score_to_impact(score: float) -> CIAImpact:
            if score >= 0.8:
                return CIAImpact.HIGH
            elif score >= 0.5:
                return CIAImpact.MEDIUM
            elif score >= 0.1:
                return CIAImpact.LOW
            else:
                return CIAImpact.NONE
        
        return CIATriad(
            confidentiality=score_to_impact(c_score),
            integrity=score_to_impact(i_score),
            availability=score_to_impact(a_score)
        )