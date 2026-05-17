# 📚 Agent Stack Usage Examples

This document provides detailed examples of using the Multi-Agent Security Stack for various security operations.

---

## Table of Contents
- [Complete Security Assessment](#complete-security-assessment)
- [Attack Surface Mapping](#attack-surface-mapping)
- [Threat Modeling Workflow](#threat-modeling-workflow)
- [Security Operations Center (SOC)](#security-operations-center-soc)
- [Incident Response](#incident-response)
- [Combining Multiple Agents](#combining-multiple-agents)

---

## Complete Security Assessment

**Scenario**: You're building a new web application and need a comprehensive security review before launch.

```python
# 1. Run full assessment
target = "web_app"
assessment = full_security_assessment(target)

# Assessment includes:
# - System topology map with all components
# - Identified single points of failure (SPOF)
# - Complete threat model with attack vectors
# - Failure simulations for critical components
# - Recommended security drills
# - Overall risk score (0-100)
```

**Sample Output**:
```json
{
  "target": "web_app",
  "system_map": {
    "nodes": {
      "frontend": {"type": "service", "dependencies": ["api_gateway"]},
      "api_gateway": {"type": "service", "dependencies": ["auth_service", "app_service"]},
      "auth_service": {"type": "service", "dependencies": ["user_db", "session_store"]},
      "main_db": {"type": "database", "dependencies": []}
    },
    "single_points_of_failure": ["api_gateway", "main_db"]
  },
  "threat_model": {
    "critical_threats": 3,
    "threats": [
      {
        "name": "Data Exfiltration from main_db",
        "severity": "critical",
        "mitigations": ["Encrypt at rest", "Network segmentation"]
      }
    ]
  },
  "overall_risk_score": {
    "score": 65,
    "level": "HIGH"
  }
}
```

**What to do next**:
1. Review all critical threats immediately
2. Address SPOF with redundancy
3. Schedule recommended security drills
4. Implement suggested mitigations

---

## Attack Surface Mapping

**Scenario**: You need to understand your attack surface before a pentest engagement.

### Step 1: Map the System

```python
# Map your infrastructure
system_map = map_system("network")
```

**Output**:
- Network topology with all nodes
- Dependency chains
- Critical execution paths
- Feedback loops

### Step 2: Analyze Blast Radius

```python
# What happens if the DMZ is compromised?
blast_radius = analyze_blast_radius("dmz")
```

**Output**:
```json
{
  "node": "dmz",
  "directly_affected": ["web_server", "internal_network"],
  "cascading_failures": ["web_server", "app_server", "database_server"],
  "total_impact_percentage": 57.1,
  "recommendation": "CRITICAL - Single Point of Failure"
}
```

**Interpretation**:
- DMZ compromise affects 57% of your infrastructure
- Direct path to internal network and databases
- **Action**: Implement strict network segmentation and monitoring

### Step 3: Map All Critical Nodes

```python
# Get SPOF list from system map
spof = system_map["single_points_of_failure"]

# Analyze each one
for node in spof:
    impact = analyze_blast_radius(node)
    print(f"{node}: {impact['total_impact_percentage']}% impact")
```

---

## Threat Modeling Workflow

**Scenario**: New authentication system needs threat modeling.

### Step 1: Generate Initial Threat Model

```python
# Model the authentication service
threats = threat_model_system("web_app")
```

**Key Outputs**:
- Authentication bypass threats
- Lateral movement vectors
- Trust boundary violations
- Suggested mitigations

### Step 2: Assume-Breach Analysis

```python
# Simulate attacker compromising the frontend
breach_analysis = assume_breach("frontend", "web_app")
```

**Output**:
```json
{
  "entry_point": "frontend",
  "assumption": "Attacker has full control of this component",
  "reachable_components": [
    "frontend", "api_gateway", "auth_service", "app_service",
    "user_db", "main_db", "session_store", "cache"
  ],
  "high_value_targets_at_risk": ["user_db", "main_db"],
  "recommended_containment": [
    "URGENT: Blast radius too large - redesign network topology",
    "Implement network segmentation to isolate frontend",
    "Deploy micro-segmentation with zero-trust policies"
  ]
}
```

**Critical Insight**: Frontend compromise leads to full system access!

### Step 3: Implement Mitigations

Based on the analysis:
1. Add network segmentation between frontend and backend
2. Implement zero-trust policies
3. Deploy micro-segmentation
4. Add runtime security monitoring
5. Re-run `assume_breach` to verify improvements

---

## Security Operations Center (SOC)

**Scenario**: You're running a SOC and need to analyze security events.

### Log Analysis

```python
# Analyze auth logs
logs = """
2024-01-15 10:23:45 INFO: Login successful for user alice from 192.168.1.10
2024-01-15 10:24:12 ERROR: Authentication failed for user admin from 45.67.89.10
2024-01-15 10:24:15 ERROR: Authentication failed for user admin from 45.67.89.10
2024-01-15 10:24:18 ERROR: Authentication failed for user admin from 45.67.89.10
2024-01-15 10:24:21 ERROR: Authentication failed for user root from 45.67.89.10
2024-01-15 10:24:24 ERROR: Authentication failed for user administrator from 45.67.89.10
2024-01-15 10:25:30 WARNING: Multiple failed login attempts from 45.67.89.10
2024-01-15 10:26:00 ERROR: Account locked for user admin
"""

analysis = analyze_logs(logs, time_window="1h")
```

**Output**:
```json
{
  "patterns": {
    "failed": 5,
    "error": 6,
    "warning": 1
  },
  "anomalies": [
    {
      "pattern": "High frequency of 'failed' events",
      "severity": "high",
      "context": {"percentage": 62.5}
    }
  ],
  "security_events": [
    "ERROR: Authentication failed for user admin from 45.67.89.10",
    "WARNING: Multiple failed login attempts from 45.67.89.10"
  ]
}
```

**Detection**: Brute force attack from 45.67.89.10

### Anomaly Detection

```python
# Monitor system metrics
metrics = {
    "failed_logins": 150,      # Baseline: 10
    "cpu_usage": 95,           # Baseline: 45
    "response_time_ms": 3000,  # Baseline: 200
    "active_sessions": 500     # Baseline: 400
}

anomalies = detect_anomalies(metrics)
```

**Output**:
```json
{
  "anomalies_detected": 3,
  "alert_worthy": [
    {
      "source": "failed_logins",
      "pattern": "Deviation of 1400% from baseline",
      "severity": "high"
    },
    {
      "source": "cpu_usage",
      "pattern": "Deviation of 111% from baseline",
      "severity": "high"
    }
  ]
}
```

### Event Correlation

```python
# Correlate suspicious events
events = [
    {"timestamp": "2024-01-15T10:24:12", "source_ip": "45.67.89.10", "event": "failed_login", "user": "admin"},
    {"timestamp": "2024-01-15T10:24:15", "source_ip": "45.67.89.10", "event": "failed_login", "user": "admin"},
    {"timestamp": "2024-01-15T10:24:18", "source_ip": "45.67.89.10", "event": "failed_login", "user": "admin"},
    {"timestamp": "2024-01-15T10:24:21", "source_ip": "45.67.89.10", "event": "failed_login", "user": "root"},
    {"timestamp": "2024-01-15T10:24:24", "source_ip": "45.67.89.10", "event": "failed_login", "user": "administrator"},
]

correlation = correlate_security_events(events)
```

**Output**:
```json
{
  "incident_chains": 1,
  "potential_attacks": [
    [
      {"source_ip": "45.67.89.10", "event": "failed_login", "user": "admin"},
      {"source_ip": "45.67.89.10", "event": "failed_login", "user": "admin"},
      {"source_ip": "45.67.89.10", "event": "failed_login", "user": "root"},
      {"source_ip": "45.67.89.10", "event": "failed_login", "user": "administrator"}
    ]
  ]
}
```

**Attack Identified**: Coordinated brute force attack trying multiple admin accounts

---

## Incident Response

**Scenario**: Database breach detected, need immediate response plan.

### Step 1: Create Incident Runbook

```python
runbook = create_incident_runbook(
    scenario="database breach",
    severity="critical"
)
```

**Output**:
```json
{
  "runbook_id": "RB-001",
  "scenario": "database breach",
  "severity": "critical",
  "steps": [
    {"step": 1, "action": "Acknowledge incident and assemble response team", "role": "on-call"},
    {"step": 2, "action": "Assess scope and impact", "role": "incident_commander"},
    {"step": 3, "action": "Isolate affected systems from network", "role": "security_engineer"},
    {"step": 4, "action": "Preserve forensic evidence", "role": "security_engineer"},
    {"step": 5, "action": "Identify attack vector and entry point", "role": "security_analyst"},
    {"step": 6, "action": "Rotate all credentials", "role": "security_engineer"},
    {"step": 7, "action": "Patch identified vulnerabilities", "role": "devops"},
    {"step": 8, "action": "Conduct post-incident review", "role": "incident_commander"}
  ],
  "escalation_path": ["on-call", "team_lead", "engineering_manager", "vp_engineering", "cto"],
  "estimated_mttr": "40-80 minutes"
}
```

### Step 2: Assess Impact

```python
# Simulate the breach impact
impact = simulate_component_failure("main_db", "web_app")
```

**Output**:
```json
{
  "failed_component": "main_db",
  "affected_components": ["main_db", "app_service", "cache"],
  "impact_percentage": 37.5,
  "severity": "medium",
  "estimated_recovery_time": "30-60 minutes"
}
```

### Step 3: Execute Runbook

Follow the steps from the runbook in order, escalating as needed.

### Step 4: Post-Incident Learning

After resolution, update the runbook:

```python
incident_data = {
    "resolution_time_minutes": 95,
    "learnings": [
        "Add database activity monitoring",
        "Implement query parameterization checks",
        "Deploy honeypot database",
        "Schedule quarterly SQL injection drills"
    ]
}

updated_runbook = update_playbook("RB-001", incident_data)
```

---

## Combining Multiple Agents

**Scenario**: Purple team exercise - comprehensive security validation.

### Agent Stack: Security Review

```python
# 1. Map the target system
system_map = map_system("web_app")

# 2. Identify high-value targets
spof = system_map["single_points_of_failure"]
print(f"Critical components: {spof}")

# 3. Threat model the system
threats = threat_model_system("web_app")
critical_threats = [t for t in threats["threats"] if t["severity"] == "critical"]

# 4. For each critical component, simulate breach
for component in spof:
    breach = assume_breach(component, "web_app")
    print(f"\nBreach from {component}:")
    print(f"  - Reachable: {len(breach['reachable_components'])} components")
    print(f"  - HVT at risk: {breach['high_value_targets_at_risk']}")

# 5. Create incident runbooks for each threat
for threat in critical_threats[:3]:  # Top 3 critical threats
    runbook = create_incident_runbook(
        threat["name"],
        severity="critical"
    )
    print(f"\nRunbook {runbook['runbook_id']} created for {threat['name']}")

# 6. Generate security drills
drills = suggest_security_drills("web_app")
print(f"\n{len(drills['drills'])} security drills recommended")

# 7. Simulate failure scenarios
for component in spof[:2]:  # Top 2 SPOF
    simulation = simulate_component_failure(component, "web_app")
    print(f"\n{component} failure impacts {simulation['impact_percentage']}% of system")
```

**Output Summary**:
- System mapped with 8 components
- 2 single points of failure identified
- 3 critical threats found
- 3 incident runbooks created
- 3 security drills recommended
- Failure scenarios simulated

**Next Steps**:
1. Address SPOF with redundancy
2. Implement critical threat mitigations
3. Schedule and execute security drills
4. Deploy monitoring for early detection
5. Re-assess after changes

---

## Advanced Patterns

### Custom Agent Stacks

**SOC Automation Stack**:
```python
# Automated security monitoring workflow
def soc_analysis_pipeline(log_stream, metrics):
    # Stage 1: Signal Distiller
    log_analysis = analyze_logs(log_stream, "1h")
    anomalies = detect_anomalies(metrics)

    # Stage 2: Red-Teamed Architect (if anomalies detected)
    if anomalies["alert_worthy"]:
        # Assess potential attack paths
        breach_analysis = assume_breach("entry_point", "system")

        # Stage 3: On-Call Strategist
        if breach_analysis["high_value_targets_at_risk"]:
            # Auto-generate incident response
            runbook = create_incident_runbook(
                "potential_breach_detected",
                severity="high"
            )
            # Alert team with runbook
            return {"alert": True, "runbook": runbook}

    return {"alert": False}
```

**Continuous Threat Modeling**:
```python
# Run after each deployment
def post_deployment_security_check(system):
    # Re-map system
    new_map = map_system(system)

    # Re-threat model
    new_threats = threat_model_system(system)

    # Check for new SPOF
    new_spof = new_map["single_points_of_failure"]

    # Alert if risk increased
    risk = full_security_assessment(system)
    if risk["overall_risk_score"]["score"] > 70:
        print("⚠️  DEPLOYMENT INCREASED RISK - REVIEW REQUIRED")

    return risk
```

---

## Tips and Best Practices

### 1. Start with Full Assessment
Always run `full_security_assessment` first to get the complete picture.

### 2. Iterate on Threat Models
Threat modeling is not one-time:
- Re-run after architecture changes
- Update when new features are added
- Refresh quarterly as threat landscape evolves

### 3. Automate Monitoring
Integrate Signal Distiller into your SIEM/logging pipeline for continuous anomaly detection.

### 4. Practice Incident Response
Use On-Call Strategist to create runbooks, then practice them through drills.

### 5. Assume Breach Everywhere
Run assume-breach analysis on every component, especially:
- Public-facing services
- Components with external dependencies
- Services with elevated privileges

### 6. Track Risk Over Time
```python
# Store assessment results
risk_history = []
risk_history.append({
    "date": "2024-01-15",
    "score": full_security_assessment("web_app")["overall_risk_score"]
})
# Monitor trend - risk should decrease over time
```

---

## Integration Examples

### CI/CD Pipeline
```yaml
# .github/workflows/security-check.yml
- name: Security Assessment
  run: |
    python -c "
    from app.agents import AgentOrchestrator
    orch = AgentOrchestrator()
    result = orch.full_security_analysis('web_app')
    if result['overall_risk_score']['score'] > 80:
        exit(1)  # Fail build if risk too high
    "
```

### Slack Alerting
```python
def alert_on_critical_threats(system):
    threats = threat_model_system(system)
    critical = [t for t in threats["threats"] if t["severity"] == "critical"]

    if critical:
        send_slack_alert(
            f"🚨 {len(critical)} critical threats detected!",
            json.dumps(critical, indent=2)
        )
```

---

**Need more examples?** Check the agent implementations in `app/agents.py` for detailed docstrings and method signatures.
