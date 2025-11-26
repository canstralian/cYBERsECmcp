from app.context import AppContext
from mcp.server.fastmcp import FastMCP
from app.agents import (
    AgentOrchestrator,
    SystemsCartographer,
    RedTeamedArchitect,
    SignalDistiller,
    OnCallStrategist
)
import json
from typing import Optional


# Initialize agent stack (singleton pattern)
orchestrator = AgentOrchestrator()


def register_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    def query_db() -> str:
        ctx = mcp.get_context()
        app_ctx: AppContext = ctx.request_context.lifespan_context
        return app_ctx.db.query()

    @mcp.tool()
    def scan_network(target_ip: str) -> str:
        # Placeholder
        return f"Scanned network at {target_ip}, no vulnerabilities found."

    @mcp.tool()
    def run_exploit(exploit_name: str, target_ip: str) -> str:
        # Placeholder
        return f"Executed exploit {exploit_name} on target {target_ip}. Success!"

    # ========================================================================
    # AGENT STACK TOOLS
    # ========================================================================

    @mcp.tool()
    def map_system(target: str, config: Optional[str] = None) -> str:
        """
        Systems Cartographer: Maps complex systems into dependency graphs.
        Identifies feedback loops, dependencies, and failure modes.

        Args:
            target: System to map (e.g., 'web_app', 'network', 'api_service')
            config: Optional JSON config for the system

        Returns:
            JSON containing system map, critical paths, and SPOF analysis
        """
        config_dict = json.loads(config) if config else None
        result = orchestrator.cartographer.map_system(target, config_dict)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def analyze_blast_radius(node_id: str) -> str:
        """
        Systems Cartographer: Analyzes what happens if a component fails.
        Shows cascading failures and impact assessment.

        Args:
            node_id: Component to analyze (use map_system first to get node IDs)

        Returns:
            JSON with affected components and blast radius analysis
        """
        result = orchestrator.cartographer.analyze_blast_radius(node_id)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def threat_model_system(target: str, config: Optional[str] = None) -> str:
        """
        Red-Teamed Architect: Performs comprehensive threat modeling.
        Assumes breach and identifies attack vectors.

        Args:
            target: System to threat model
            config: Optional system configuration JSON

        Returns:
            JSON with identified threats, severity, and mitigations
        """
        # First map the system
        config_dict = json.loads(config) if config else None
        system_map = orchestrator.cartographer.map_system(target, config_dict)

        # Then threat model it
        result = orchestrator.architect.threat_model(system_map)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def assume_breach(entry_point: str, target: str) -> str:
        """
        Red-Teamed Architect: Assumes attacker has compromised entry point.
        Maps lateral movement paths and privilege escalation routes.

        Args:
            entry_point: Compromised component (node ID from system map)
            target: System being analyzed

        Returns:
            JSON with attack paths and containment recommendations
        """
        # Map system first
        system_map = orchestrator.cartographer.map_system(target)

        # Run breach analysis
        result = orchestrator.architect.assume_breach_analysis(entry_point, system_map)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def analyze_logs(log_data: str, time_window: str = "24h") -> str:
        """
        Signal Distiller: Analyzes log streams for patterns and anomalies.
        Strips noise and surfaces security-relevant events.

        Args:
            log_data: JSON array of log entries
            time_window: Analysis time window (e.g., '24h', '1w')

        Returns:
            JSON with patterns, anomalies, and security events
        """
        logs = json.loads(log_data) if log_data.startswith('[') else log_data.split('\n')
        result = orchestrator.distiller.analyze_logs(logs, time_window)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def detect_anomalies(metrics: str) -> str:
        """
        Signal Distiller: Detects anomalies in metrics data.
        Compares against baseline and identifies deviations.

        Args:
            metrics: JSON object with metric names and values

        Returns:
            JSON with detected anomalies and alert-worthy events
        """
        metrics_dict = json.loads(metrics)
        result = orchestrator.distiller.detect_anomalies(metrics_dict)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def correlate_security_events(events: str) -> str:
        """
        Signal Distiller: Correlates related security events to identify attack chains.

        Args:
            events: JSON array of security events

        Returns:
            JSON with incident chains and potential attacks
        """
        events_list = json.loads(events)
        result = orchestrator.distiller.correlate_events(events_list)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def create_incident_runbook(scenario: str, severity: str = "medium") -> str:
        """
        On-Call Strategist: Creates incident response runbook.
        Generates step-by-step procedures for incident scenarios.

        Args:
            scenario: Incident scenario (e.g., 'database breach', 'service outage')
            severity: Severity level (critical, high, medium, low)

        Returns:
            JSON with runbook steps and escalation paths
        """
        result = orchestrator.strategist.create_runbook(scenario, severity)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def simulate_component_failure(component: str, target: str) -> str:
        """
        On-Call Strategist: Simulates component failure and predicts impact.

        Args:
            component: Component to simulate failure for
            target: System being analyzed

        Returns:
            JSON with impact analysis and recovery plan
        """
        # Map system first
        system_map = orchestrator.cartographer.map_system(target)

        # Simulate failure
        result = orchestrator.strategist.simulate_outage(component, system_map)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def suggest_security_drills(target: str) -> str:
        """
        On-Call Strategist: Suggests disaster recovery and security drills.

        Args:
            target: System to generate drills for

        Returns:
            JSON with recommended drill scenarios
        """
        # Map system first
        system_map = orchestrator.cartographer.map_system(target)

        # Generate drill suggestions
        result = orchestrator.strategist.suggest_drills(system_map)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def full_security_assessment(target: str, config: Optional[str] = None) -> str:
        """
        Agent Orchestrator: Runs complete security analysis using all agents.
        Provides comprehensive security assessment with system mapping,
        threat modeling, failure simulation, and recommendations.

        Args:
            target: System to analyze
            config: Optional system configuration JSON

        Returns:
            JSON with complete security analysis and risk score
        """
        config_dict = json.loads(config) if config else None
        result = orchestrator.full_security_analysis(target, config_dict)
        return json.dumps(result, indent=2)
