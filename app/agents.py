"""
Multi-Agent Security Stack
Implements four complementary AI agents for cybersecurity operations.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class SystemNode:
    """Represents a component in the system."""
    id: str
    name: str
    type: str  # service, database, api, frontend, etc.
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemMap:
    """Complete system topology."""
    nodes: Dict[str, SystemNode] = field(default_factory=dict)
    edges: List[tuple] = field(default_factory=list)
    feedback_loops: List[List[str]] = field(default_factory=list)


@dataclass
class Threat:
    """Security threat identified by the Red-Teamed Architect."""
    id: str
    name: str
    severity: str  # critical, high, medium, low
    attack_vector: str
    affected_components: List[str]
    mitigations: List[str] = field(default_factory=list)
    assumes_breach: bool = False


@dataclass
class Anomaly:
    """Detected anomaly from Signal Distiller."""
    timestamp: str
    source: str
    pattern: str
    severity: str
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Runbook:
    """Incident response runbook."""
    scenario: str
    severity: str
    steps: List[Dict[str, str]]
    escalation_path: List[str]
    required_roles: List[str]


# ============================================================================
# AGENT 1: SYSTEMS CARTOGRAPHER
# ============================================================================

class SystemsCartographer:
    """
    Maps complex systems into clear diagrams and narratives.
    Obsessed with feedback loops, dependencies, and failure modes.
    Always asks: 'What happens if this node dies?'
    """

    def __init__(self):
        self.system_map = SystemMap()

    def map_system(self, target: str, config: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Analyzes a target system and creates a dependency map.

        Args:
            target: System identifier or configuration
            config: Optional system configuration data

        Returns:
            Dictionary containing nodes, edges, and analysis
        """
        # TODO: Integrate with actual system discovery tools
        # For now, create a representative example for pentesting infrastructure

        if "web_app" in target.lower():
            self._map_web_application(target, config or {})
        elif "network" in target.lower():
            self._map_network_infrastructure(target, config or {})
        else:
            self._map_generic_system(target, config or {})

        return {
            "nodes": {k: vars(v) for k, v in self.system_map.nodes.items()},
            "edges": self.system_map.edges,
            "feedback_loops": self.system_map.feedback_loops,
            "critical_paths": self._identify_critical_paths(),
            "single_points_of_failure": self._find_spof(),
            "summary": self._generate_narrative()
        }

    def analyze_blast_radius(self, node_id: str) -> Dict[str, Any]:
        """
        Determines what fails if this node goes down.

        Returns cascade analysis and impact assessment.
        """
        if node_id not in self.system_map.nodes:
            return {"error": f"Node {node_id} not found in system map"}

        affected = self._find_dependent_nodes(node_id)
        cascading_failures = self._simulate_cascade(node_id)

        return {
            "node": node_id,
            "directly_affected": affected,
            "cascading_failures": cascading_failures,
            "total_impact_percentage": len(cascading_failures) / len(self.system_map.nodes) * 100,
            "recommendation": "CRITICAL - Single Point of Failure" if len(cascading_failures) > len(self.system_map.nodes) / 2 else "Monitor closely"
        }

    def _map_web_application(self, target: str, config: Dict):
        """Maps a typical web application stack."""
        nodes = {
            "frontend": SystemNode("frontend", "Web Frontend", "service", ["api_gateway"]),
            "api_gateway": SystemNode("api_gateway", "API Gateway", "service", ["auth_service", "app_service"]),
            "auth_service": SystemNode("auth_service", "Authentication", "service", ["user_db", "session_store"]),
            "app_service": SystemNode("app_service", "Application Logic", "service", ["main_db", "cache"]),
            "user_db": SystemNode("user_db", "User Database", "database", []),
            "main_db": SystemNode("main_db", "Main Database", "database", []),
            "session_store": SystemNode("session_store", "Session Store", "cache", []),
            "cache": SystemNode("cache", "Application Cache", "cache", ["main_db"]),
        }

        self.system_map.nodes = nodes
        self.system_map.edges = [(n.id, dep) for n in nodes.values() for dep in n.dependencies]
        self.system_map.feedback_loops = [["cache", "main_db", "app_service"]]

    def _map_network_infrastructure(self, target: str, config: Dict):
        """Maps network infrastructure."""
        nodes = {
            "firewall": SystemNode("firewall", "Perimeter Firewall", "security", ["dmz"]),
            "dmz": SystemNode("dmz", "DMZ", "network", ["web_server", "internal_network"]),
            "web_server": SystemNode("web_server", "Web Server", "service", ["app_server"]),
            "app_server": SystemNode("app_server", "Application Server", "service", ["database_server"]),
            "database_server": SystemNode("database_server", "Database Server", "database", []),
            "internal_network": SystemNode("internal_network", "Internal Network", "network", ["app_server", "admin_workstation"]),
            "admin_workstation": SystemNode("admin_workstation", "Admin Workstation", "endpoint", []),
        }

        self.system_map.nodes = nodes
        self.system_map.edges = [(n.id, dep) for n in nodes.values() for dep in n.dependencies]

    def _map_generic_system(self, target: str, config: Dict):
        """Creates a generic system map."""
        self.system_map.nodes = {
            "entry": SystemNode("entry", "Entry Point", "service", ["core"]),
            "core": SystemNode("core", "Core System", "service", ["storage"]),
            "storage": SystemNode("storage", "Data Storage", "database", []),
        }
        self.system_map.edges = [("entry", "core"), ("core", "storage")]

    def _identify_critical_paths(self) -> List[List[str]]:
        """Identifies critical execution paths through the system."""
        # Simple implementation - find longest dependency chains
        paths = []
        for node_id in self.system_map.nodes:
            path = self._trace_dependency_chain(node_id)
            if len(path) > 2:
                paths.append(path)
        return paths

    def _trace_dependency_chain(self, node_id: str, visited=None) -> List[str]:
        """Recursively traces dependency chains."""
        if visited is None:
            visited = set()
        if node_id in visited:
            return []

        visited.add(node_id)
        node = self.system_map.nodes.get(node_id)
        if not node or not node.dependencies:
            return [node_id]

        chains = [[node_id] + self._trace_dependency_chain(dep, visited.copy())
                  for dep in node.dependencies]
        return max(chains, key=len) if chains else [node_id]

    def _find_spof(self) -> List[str]:
        """Finds single points of failure."""
        spof = []
        for node_id in self.system_map.nodes:
            # A node is SPOF if many others depend on it
            dependents = [n for n in self.system_map.nodes.values()
                         if node_id in n.dependencies]
            if len(dependents) >= 2:
                spof.append(node_id)
        return spof

    def _find_dependent_nodes(self, node_id: str) -> List[str]:
        """Finds all nodes that directly depend on this node."""
        return [n.id for n in self.system_map.nodes.values()
                if node_id in n.dependencies]

    def _simulate_cascade(self, node_id: str, failed=None) -> List[str]:
        """Simulates cascading failures."""
        if failed is None:
            failed = set()

        failed.add(node_id)
        dependents = self._find_dependent_nodes(node_id)

        for dep in dependents:
            if dep not in failed:
                self._simulate_cascade(dep, failed)

        return list(failed)

    def _generate_narrative(self) -> str:
        """Generates human-readable system description."""
        node_count = len(self.system_map.nodes)
        edge_count = len(self.system_map.edges)
        spof = self._find_spof()

        narrative = f"System contains {node_count} components with {edge_count} dependencies. "
        if spof:
            narrative += f"WARNING: {len(spof)} single points of failure detected: {', '.join(spof)}. "
        if self.system_map.feedback_loops:
            narrative += f"{len(self.system_map.feedback_loops)} feedback loops identified. "

        return narrative


# ============================================================================
# AGENT 2: RED-TEAMED ARCHITECT
# ============================================================================

class RedTeamedArchitect:
    """
    Designs systems as if an attacker already lives inside them.
    Threat-models every feature, assumes credential leaks,
    suggests minimal, enforced boundaries. Paranoid, but politely so.
    """

    def __init__(self):
        self.threats = []
        self.trust_boundaries = []

    def threat_model(self, system_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Performs comprehensive threat modeling on a system map.
        Assumes breach and identifies attack paths.
        """
        threats = []
        nodes = system_map.get("nodes", {})
        edges = system_map.get("edges", [])

        # Analyze each component for threats
        for node_id, node_data in nodes.items():
            node_type = node_data.get("type", "")

            # Check for common threat patterns
            if node_type == "database":
                threats.append(Threat(
                    id=f"T-{len(threats)+1:03d}",
                    name=f"Data Exfiltration from {node_id}",
                    severity="critical",
                    attack_vector="SQL injection or compromised credentials",
                    affected_components=[node_id],
                    mitigations=["Encrypt at rest", "Network segmentation", "Query parameterization", "Audit logging"]
                ))

            if node_type == "service":
                threats.append(Threat(
                    id=f"T-{len(threats)+1:03d}",
                    name=f"Lateral Movement via {node_id}",
                    severity="high",
                    attack_vector="Compromised service credentials or vulnerabilities",
                    affected_components=[node_id] + node_data.get("dependencies", []),
                    mitigations=["Principle of least privilege", "Service mesh with mTLS", "Runtime security monitoring"],
                    assumes_breach=True
                ))

            if "auth" in node_id.lower() or "session" in node_id.lower():
                threats.append(Threat(
                    id=f"T-{len(threats)+1:03d}",
                    name=f"Authentication Bypass in {node_id}",
                    severity="critical",
                    attack_vector="Token theft, session hijacking, or credential stuffing",
                    affected_components=[node_id],
                    mitigations=["MFA required", "Short-lived tokens", "Anomaly detection", "Hardware-backed keys"]
                ))

        # Analyze trust boundaries
        trust_violations = self._analyze_trust_boundaries(nodes, edges)

        self.threats = threats
        return {
            "threats": [vars(t) for t in threats],
            "threat_count": len(threats),
            "critical_threats": len([t for t in threats if t.severity == "critical"]),
            "trust_boundary_violations": trust_violations,
            "assume_breach_scenarios": [vars(t) for t in threats if t.assumes_breach],
            "recommendations": self._generate_security_recommendations(threats)
        }

    def assume_breach_analysis(self, entry_point: str, system_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assumes an attacker has compromised the entry point.
        Maps potential lateral movement and privilege escalation paths.
        """
        nodes = system_map.get("nodes", {})
        edges = system_map.get("edges", [])

        if entry_point not in nodes:
            return {"error": f"Entry point {entry_point} not found"}

        # Build attack graph from entry point
        attack_paths = self._find_attack_paths(entry_point, nodes, edges)
        high_value_targets = self._identify_high_value_targets(nodes)

        return {
            "entry_point": entry_point,
            "assumption": "Attacker has full control of this component",
            "reachable_components": attack_paths,
            "high_value_targets_at_risk": [t for t in high_value_targets if t in attack_paths],
            "recommended_containment": self._suggest_containment(entry_point, attack_paths),
            "detection_opportunities": self._suggest_detection_points(entry_point, attack_paths)
        }

    def _analyze_trust_boundaries(self, nodes: Dict, edges: List) -> List[Dict]:
        """Identifies trust boundary violations."""
        violations = []

        # Check for direct connections that cross trust zones
        trust_zones = {
            "public": ["frontend", "web_server"],
            "internal": ["api_gateway", "app_service", "app_server"],
            "restricted": ["user_db", "main_db", "database_server", "admin_workstation"]
        }

        for source, target in edges:
            source_zone = self._get_trust_zone(source, trust_zones)
            target_zone = self._get_trust_zone(target, trust_zones)

            if source_zone and target_zone and source_zone != target_zone:
                # Check if crossing from less to more trusted
                zone_order = ["public", "internal", "restricted"]
                if zone_order.index(source_zone) < zone_order.index(target_zone):
                    violations.append({
                        "source": source,
                        "target": target,
                        "source_zone": source_zone,
                        "target_zone": target_zone,
                        "risk": "Potential unauthorized access from less trusted zone"
                    })

        return violations

    def _get_trust_zone(self, node_id: str, trust_zones: Dict) -> Optional[str]:
        """Determines which trust zone a node belongs to."""
        for zone, nodes in trust_zones.items():
            if any(pattern in node_id for pattern in nodes):
                return zone
        return None

    def _find_attack_paths(self, start: str, nodes: Dict, edges: List, max_depth: int = 5) -> List[str]:
        """Finds all nodes reachable from the compromised entry point."""
        reachable = set()
        queue = [(start, 0)]
        visited = {start}

        while queue:
            current, depth = queue.pop(0)
            if depth >= max_depth:
                continue

            reachable.add(current)

            # Find connected nodes (bi-directional traversal simulates lateral movement)
            connected = [target for source, target in edges if source == current]
            connected += [source for source, target in edges if target == current]

            for node in connected:
                if node not in visited:
                    visited.add(node)
                    queue.append((node, depth + 1))

        return list(reachable)

    def _identify_high_value_targets(self, nodes: Dict) -> List[str]:
        """Identifies high-value targets for attackers."""
        hvt = []
        for node_id, node_data in nodes.items():
            node_type = node_data.get("type", "")
            if node_type in ["database", "auth"]:
                hvt.append(node_id)
            if "admin" in node_id.lower() or "db" in node_id.lower():
                hvt.append(node_id)
        return hvt

    def _suggest_containment(self, entry_point: str, reachable: List[str]) -> List[str]:
        """Suggests containment strategies."""
        suggestions = [
            f"Implement network segmentation to isolate {entry_point}",
            "Deploy micro-segmentation with zero-trust policies",
            f"Monitor all traffic from {entry_point} for anomalies",
            "Implement strict egress filtering",
            "Require step-up authentication for lateral movement"
        ]

        if len(reachable) > 5:
            suggestions.insert(0, "URGENT: Blast radius too large - redesign network topology")

        return suggestions

    def _suggest_detection_points(self, entry_point: str, reachable: List[str]) -> List[Dict]:
        """Suggests where to place detection mechanisms."""
        return [
            {"location": entry_point, "detection": "Behavioral analysis for anomalous activity"},
            {"location": "network", "detection": "East-west traffic monitoring"},
            {"location": "endpoints", "detection": "EDR on all reachable components"},
            {"location": "data_layer", "detection": "Database activity monitoring"}
        ]

    def _generate_security_recommendations(self, threats: List[Threat]) -> List[str]:
        """Generates prioritized security recommendations."""
        recs = []
        critical_count = len([t for t in threats if t.severity == "critical"])

        if critical_count > 0:
            recs.append(f"URGENT: Address {critical_count} critical threats immediately")

        recs.extend([
            "Implement defense in depth with multiple security layers",
            "Adopt zero-trust architecture - verify explicitly, use least privilege",
            "Deploy continuous monitoring and automated threat detection",
            "Conduct regular red team exercises and breach simulations",
            "Implement security chaos engineering to test resilience"
        ])

        return recs


# ============================================================================
# AGENT 3: SIGNAL DISTILLER
# ============================================================================

class SignalDistiller:
    """
    Lives in log streams, metrics, and event firehoses.
    Strips noise, surfaces patterns, auto-builds dashboards.
    Obsessed with baselines and 'what changed in the last 24 hours.'
    """

    def __init__(self):
        self.baselines = {}
        self.anomalies = []

    def analyze_logs(self, log_data: List[str], time_window: str = "24h") -> Dict[str, Any]:
        """
        Analyzes log streams for patterns and anomalies.

        Args:
            log_data: List of log entries
            time_window: Time window for analysis

        Returns:
            Patterns, anomalies, and key events
        """
        # Parse and categorize logs
        patterns = self._extract_patterns(log_data)
        anomalies = self._detect_log_anomalies(log_data, patterns)

        # Identify security-relevant events
        security_events = self._filter_security_events(log_data)

        return {
            "total_events": len(log_data),
            "time_window": time_window,
            "patterns": patterns,
            "anomalies": [vars(a) for a in anomalies],
            "security_events": security_events,
            "recommendations": self._generate_log_recommendations(anomalies),
            "summary": f"Analyzed {len(log_data)} events, found {len(anomalies)} anomalies"
        }

    def detect_anomalies(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detects anomalies in metrics data.
        Compares against baseline and identifies deviations.
        """
        anomalies = []

        for metric_name, value in metrics.items():
            baseline = self.baselines.get(metric_name)

            if baseline is None:
                # Establish baseline
                self.baselines[metric_name] = value
                continue

            # Simple threshold-based anomaly detection
            deviation = abs(value - baseline) / baseline if baseline != 0 else 0

            if deviation > 0.3:  # 30% deviation threshold
                anomaly = Anomaly(
                    timestamp=datetime.now().isoformat(),
                    source=metric_name,
                    pattern=f"Deviation of {deviation*100:.1f}% from baseline",
                    severity="high" if deviation > 0.5 else "medium",
                    context={"current": value, "baseline": baseline, "deviation": deviation}
                )
                anomalies.append(anomaly)

        self.anomalies.extend(anomalies)

        return {
            "anomalies_detected": len(anomalies),
            "anomalies": [vars(a) for a in anomalies],
            "baselines": self.baselines,
            "alert_worthy": [vars(a) for a in anomalies if a.severity == "high"]
        }

    def correlate_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Correlates related security events to identify attack chains.
        """
        # Group events by time proximity and related entities
        incident_chains = []
        timeline = sorted(events, key=lambda e: e.get("timestamp", ""))

        current_chain = []
        for event in timeline:
            if not current_chain:
                current_chain.append(event)
            else:
                # Check if event is related (same source IP, user, etc.)
                if self._events_related(current_chain[-1], event):
                    current_chain.append(event)
                else:
                    if len(current_chain) > 1:
                        incident_chains.append(current_chain)
                    current_chain = [event]

        if len(current_chain) > 1:
            incident_chains.append(current_chain)

        return {
            "total_events": len(events),
            "incident_chains": len(incident_chains),
            "chains": incident_chains,
            "potential_attacks": [c for c in incident_chains if len(c) >= 3],
            "summary": f"Identified {len(incident_chains)} related event sequences"
        }

    def generate_baseline(self, time_window: str, sample_data: Dict[str, List]) -> Dict[str, Any]:
        """
        Generates baseline profiles for normal behavior.
        """
        baselines = {}

        for metric_name, values in sample_data.items():
            if values:
                baselines[metric_name] = {
                    "mean": sum(values) / len(values),
                    "min": min(values),
                    "max": max(values),
                    "sample_size": len(values)
                }

        self.baselines = {k: v["mean"] for k, v in baselines.items()}

        return {
            "time_window": time_window,
            "baselines": baselines,
            "metrics_profiled": len(baselines),
            "summary": f"Established baselines for {len(baselines)} metrics over {time_window}"
        }

    def _extract_patterns(self, logs: List[str]) -> Dict[str, int]:
        """Extracts common patterns from logs."""
        patterns = {}

        # Simple pattern extraction - count common keywords
        keywords = ["error", "warning", "failed", "success", "authentication",
                   "unauthorized", "denied", "accepted", "connection"]

        for log in logs:
            log_lower = log.lower()
            for keyword in keywords:
                if keyword in log_lower:
                    patterns[keyword] = patterns.get(keyword, 0) + 1

        return patterns

    def _detect_log_anomalies(self, logs: List[str], patterns: Dict) -> List[Anomaly]:
        """Detects anomalous log entries."""
        anomalies = []

        # Flag unusual patterns
        for pattern, count in patterns.items():
            if pattern in ["failed", "error", "denied", "unauthorized"]:
                if count > len(logs) * 0.1:  # More than 10% of logs
                    anomalies.append(Anomaly(
                        timestamp=datetime.now().isoformat(),
                        source="log_analysis",
                        pattern=f"High frequency of '{pattern}' events",
                        severity="high",
                        context={"keyword": pattern, "count": count, "percentage": count/len(logs)*100}
                    ))

        return anomalies

    def _filter_security_events(self, logs: List[str]) -> List[str]:
        """Filters logs for security-relevant events."""
        security_keywords = ["authentication", "authorization", "failed", "denied",
                           "unauthorized", "breach", "attack", "suspicious"]

        return [log for log in logs if any(kw in log.lower() for kw in security_keywords)]

    def _generate_log_recommendations(self, anomalies: List[Anomaly]) -> List[str]:
        """Generates recommendations based on log analysis."""
        if not anomalies:
            return ["No immediate issues detected. Continue monitoring."]

        return [
            f"Investigate {len(anomalies)} detected anomalies",
            "Review authentication failures for potential brute force attacks",
            "Enable enhanced logging for anomalous components",
            "Set up automated alerts for similar patterns",
            "Correlate with other data sources (network, endpoint)"
        ]

    def _events_related(self, event1: Dict, event2: Dict) -> bool:
        """Determines if two events are related."""
        # Simple heuristic - same source or target
        shared_keys = set(event1.keys()) & set(event2.keys())

        for key in ["source_ip", "user", "target", "session_id"]:
            if key in shared_keys and event1.get(key) == event2.get(key):
                return True

        return False


# ============================================================================
# AGENT 4: ON-CALL STRATEGIST
# ============================================================================

class OnCallStrategist:
    """
    Thinks in runbooks, failure trees, and incident timelines.
    Writes and updates playbooks, simulates outages, suggests drills.
    Calm, procedural, never dramatic.
    """

    def __init__(self):
        self.runbooks = {}
        self.drill_scenarios = []

    def create_runbook(self, scenario: str, severity: str = "medium") -> Dict[str, Any]:
        """
        Creates an incident response runbook for a given scenario.

        Args:
            scenario: Description of the incident type
            severity: Severity level (critical, high, medium, low)

        Returns:
            Structured runbook with steps and escalation paths
        """
        # Generate scenario-specific runbook
        runbook = self._generate_runbook_for_scenario(scenario, severity)

        runbook_id = f"RB-{len(self.runbooks)+1:03d}"
        self.runbooks[runbook_id] = runbook

        return {
            "runbook_id": runbook_id,
            "scenario": scenario,
            "severity": severity,
            "runbook": vars(runbook),
            "estimated_mttr": self._estimate_resolution_time(runbook),
            "summary": f"Runbook created with {len(runbook.steps)} response steps"
        }

    def simulate_outage(self, component: str, system_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulates an outage and predicts impact.

        Args:
            component: Component that fails
            system_map: System topology

        Returns:
            Impact analysis and response recommendations
        """
        nodes = system_map.get("nodes", {})

        if component not in nodes:
            return {"error": f"Component {component} not found"}

        # Simulate cascading failures
        affected_components = self._simulate_failure_cascade(component, nodes, system_map.get("edges", []))

        # Determine impact severity
        impact_percentage = len(affected_components) / len(nodes) * 100 if nodes else 0
        severity = self._determine_severity(impact_percentage)

        # Suggest response
        response_plan = self._generate_outage_response(component, affected_components, severity)

        return {
            "failed_component": component,
            "affected_components": affected_components,
            "impact_percentage": impact_percentage,
            "severity": severity,
            "response_plan": response_plan,
            "estimated_recovery_time": self._estimate_recovery_time(len(affected_components)),
            "rollback_options": self._suggest_rollback_options(component)
        }

    def update_playbook(self, runbook_id: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Updates a runbook based on actual incident learnings.

        Args:
            runbook_id: ID of runbook to update
            incident_data: Data from actual incident

        Returns:
            Updated runbook
        """
        if runbook_id not in self.runbooks:
            return {"error": f"Runbook {runbook_id} not found"}

        runbook = self.runbooks[runbook_id]

        # Extract learnings from incident
        learnings = incident_data.get("learnings", [])
        actual_mttr = incident_data.get("resolution_time_minutes", 0)

        # Update runbook with lessons learned
        for learning in learnings:
            runbook.steps.append({
                "step": len(runbook.steps) + 1,
                "action": learning,
                "added_from": "incident_learning"
            })

        return {
            "runbook_id": runbook_id,
            "updates_applied": len(learnings),
            "actual_mttr_minutes": actual_mttr,
            "runbook": vars(runbook),
            "summary": "Runbook updated with incident learnings"
        }

    def suggest_drills(self, system_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Suggests disaster recovery drills based on system topology.

        Returns:
            List of recommended drill scenarios
        """
        nodes = system_map.get("nodes", {})
        spof = system_map.get("single_points_of_failure", [])

        drills = []

        # SPOF failure drills
        for component in spof:
            drills.append({
                "drill_name": f"Simulate {component} Failure",
                "objective": f"Test system resilience when {component} goes down",
                "severity": "high",
                "frequency": "quarterly",
                "preparation": [
                    "Notify all stakeholders 48h in advance",
                    "Ensure monitoring is active",
                    "Prepare rollback plan"
                ],
                "execution": [
                    f"Gracefully shut down {component}",
                    "Monitor cascading effects",
                    "Execute recovery procedures",
                    "Document all observations"
                ]
            })

        # Security incident drills
        drills.append({
            "drill_name": "Ransomware Response Drill",
            "objective": "Test incident response for ransomware attack",
            "severity": "critical",
            "frequency": "semi-annual",
            "preparation": [
                "Coordinate with legal and PR teams",
                "Review backup and recovery procedures",
                "Test isolation procedures"
            ],
            "execution": [
                "Simulate detection of ransomware",
                "Execute network isolation",
                "Test backup restoration",
                "Practice stakeholder communication"
            ]
        })

        drills.append({
            "drill_name": "Credential Compromise Drill",
            "objective": "Test response to leaked admin credentials",
            "severity": "high",
            "frequency": "quarterly",
            "preparation": [
                "Create test credentials with similar privileges",
                "Set up detection mechanisms",
                "Prepare rotation procedures"
            ],
            "execution": [
                "Simulate credential leak",
                "Test detection speed",
                "Execute credential rotation",
                "Review access logs"
            ]
        })

        self.drill_scenarios = drills

        return {
            "recommended_drills": len(drills),
            "drills": drills,
            "priority_drills": [d for d in drills if d["severity"] in ["critical", "high"]],
            "summary": f"Recommended {len(drills)} disaster recovery drills"
        }

    def _generate_runbook_for_scenario(self, scenario: str, severity: str) -> Runbook:
        """Generates runbook steps based on scenario."""
        base_steps = [
            {"step": 1, "action": "Acknowledge incident and assemble response team", "role": "on-call"},
            {"step": 2, "action": "Assess scope and impact", "role": "incident_commander"},
            {"step": 3, "action": "Establish communication channels", "role": "incident_commander"},
        ]

        # Add scenario-specific steps
        if "breach" in scenario.lower() or "compromise" in scenario.lower():
            base_steps.extend([
                {"step": 4, "action": "Isolate affected systems from network", "role": "security_engineer"},
                {"step": 5, "action": "Preserve forensic evidence", "role": "security_engineer"},
                {"step": 6, "action": "Identify attack vector and entry point", "role": "security_analyst"},
                {"step": 7, "action": "Rotate all credentials", "role": "security_engineer"},
                {"step": 8, "action": "Patch identified vulnerabilities", "role": "devops"},
                {"step": 9, "action": "Restore from clean backup if necessary", "role": "devops"},
            ])
        elif "outage" in scenario.lower() or "failure" in scenario.lower():
            base_steps.extend([
                {"step": 4, "action": "Check service health and dependencies", "role": "sre"},
                {"step": 5, "action": "Review recent changes and deployments", "role": "sre"},
                {"step": 6, "action": "Attempt service restart", "role": "sre"},
                {"step": 7, "action": "Rollback recent changes if applicable", "role": "devops"},
                {"step": 8, "action": "Scale horizontally if capacity issue", "role": "sre"},
            ])
        else:
            base_steps.extend([
                {"step": 4, "action": "Investigate root cause", "role": "engineer"},
                {"step": 5, "action": "Implement temporary mitigation", "role": "engineer"},
                {"step": 6, "action": "Develop permanent fix", "role": "engineer"},
            ])

        # Add closing steps
        base_steps.extend([
            {"step": len(base_steps)+1, "action": "Verify resolution and monitor", "role": "on-call"},
            {"step": len(base_steps)+2, "action": "Conduct post-incident review", "role": "incident_commander"},
            {"step": len(base_steps)+3, "action": "Update runbooks with learnings", "role": "incident_commander"},
        ])

        escalation_path = ["on-call", "team_lead", "engineering_manager", "vp_engineering", "cto"]
        required_roles = list(set([step["role"] for step in base_steps]))

        return Runbook(
            scenario=scenario,
            severity=severity,
            steps=base_steps,
            escalation_path=escalation_path[:3] if severity in ["low", "medium"] else escalation_path,
            required_roles=required_roles
        )

    def _simulate_failure_cascade(self, component: str, nodes: Dict, edges: List) -> List[str]:
        """Simulates cascading failures from a component failure."""
        affected = {component}
        changed = True

        while changed:
            changed = False
            for node_id, node_data in nodes.items():
                if node_id in affected:
                    continue

                dependencies = node_data.get("dependencies", [])
                # If any dependency is affected, this node is affected
                if any(dep in affected for dep in dependencies):
                    affected.add(node_id)
                    changed = True

        return list(affected)

    def _determine_severity(self, impact_percentage: float) -> str:
        """Determines incident severity based on impact."""
        if impact_percentage >= 75:
            return "critical"
        elif impact_percentage >= 50:
            return "high"
        elif impact_percentage >= 25:
            return "medium"
        else:
            return "low"

    def _generate_outage_response(self, component: str, affected: List[str], severity: str) -> List[str]:
        """Generates immediate response steps for outage."""
        return [
            f"1. Page {severity} on-call engineer immediately",
            f"2. Isolate {component} to prevent cascade",
            f"3. Assess {len(affected)} affected components",
            "4. Check for available failover or backup systems",
            "5. Communicate status to stakeholders",
            f"6. Execute recovery runbook for {severity} incidents",
            "7. Monitor recovery progress",
            "8. Validate service restoration"
        ]

    def _estimate_recovery_time(self, affected_count: int) -> str:
        """Estimates recovery time based on affected components."""
        if affected_count <= 2:
            return "15-30 minutes"
        elif affected_count <= 5:
            return "30-60 minutes"
        elif affected_count <= 10:
            return "1-2 hours"
        else:
            return "2+ hours"

    def _suggest_rollback_options(self, component: str) -> List[str]:
        """Suggests rollback options."""
        return [
            f"Rollback {component} to last known good version",
            "Restore from automated backup",
            "Failover to redundant instance",
            "Scale up alternative components to handle load",
            "Activate disaster recovery site"
        ]

    def _estimate_resolution_time(self, runbook: Runbook) -> str:
        """Estimates mean time to resolution."""
        step_count = len(runbook.steps)

        if runbook.severity == "critical":
            return f"{step_count * 5}-{step_count * 10} minutes"
        elif runbook.severity == "high":
            return f"{step_count * 10}-{step_count * 15} minutes"
        else:
            return f"{step_count * 15}-{step_count * 30} minutes"


# ============================================================================
# AGENT ORCHESTRATOR
# ============================================================================

class AgentOrchestrator:
    """
    Coordinates the multi-agent security stack.
    Routes tasks to appropriate agents and combines their outputs.
    """

    def __init__(self):
        self.cartographer = SystemsCartographer()
        self.architect = RedTeamedArchitect()
        self.distiller = SignalDistiller()
        self.strategist = OnCallStrategist()

    def full_security_analysis(self, target: str, config: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Runs complete security analysis using all agents.

        Returns comprehensive security assessment.
        """
        # 1. Map the system
        system_map = self.cartographer.map_system(target, config)

        # 2. Threat model it
        threat_model = self.architect.threat_model(system_map)

        # 3. Identify SPOF and simulate failures
        spof = system_map.get("single_points_of_failure", [])
        failure_simulations = []
        for component in spof[:3]:  # Limit to top 3 SPOF
            sim = self.strategist.simulate_outage(component, system_map)
            failure_simulations.append(sim)

        # 4. Generate drills
        drills = self.strategist.suggest_drills(system_map)

        return {
            "target": target,
            "analysis_timestamp": datetime.now().isoformat(),
            "system_map": system_map,
            "threat_model": threat_model,
            "failure_simulations": failure_simulations,
            "recommended_drills": drills,
            "overall_risk_score": self._calculate_risk_score(system_map, threat_model),
            "summary": self._generate_executive_summary(system_map, threat_model, failure_simulations)
        }

    def _calculate_risk_score(self, system_map: Dict, threat_model: Dict) -> Dict[str, Any]:
        """Calculates overall risk score."""
        spof_count = len(system_map.get("single_points_of_failure", []))
        critical_threats = threat_model.get("critical_threats", 0)
        total_threats = threat_model.get("threat_count", 0)

        # Simple scoring (0-100, higher = more risk)
        risk_score = min(100, (spof_count * 10) + (critical_threats * 15) + (total_threats * 2))

        risk_level = "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 30 else "LOW"

        return {
            "score": risk_score,
            "level": risk_level,
            "factors": {
                "single_points_of_failure": spof_count,
                "critical_threats": critical_threats,
                "total_threats": total_threats
            }
        }

    def _generate_executive_summary(self, system_map: Dict, threat_model: Dict, simulations: List) -> str:
        """Generates executive summary of security posture."""
        node_count = len(system_map.get("nodes", {}))
        spof = system_map.get("single_points_of_failure", [])
        critical_threats = threat_model.get("critical_threats", 0)

        summary = f"Security analysis of {node_count}-component system completed. "

        if spof:
            summary += f"Identified {len(spof)} single points of failure: {', '.join(spof)}. "

        if critical_threats > 0:
            summary += f"Found {critical_threats} critical security threats requiring immediate attention. "

        if simulations:
            max_impact = max([s.get("impact_percentage", 0) for s in simulations])
            summary += f"Worst-case failure scenario impacts {max_impact:.0f}% of system. "

        summary += "Detailed recommendations provided."

        return summary
