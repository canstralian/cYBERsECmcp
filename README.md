---
license: apache-2.0
title: CyberSec MCP Multi-Agent Security Stack
sdk: gradio
emoji: 🛡️
colorFrom: red
colorTo: gray
short_description: Modular AI agents for pentesting, threat modeling, and incident response
sdk_version: 5.33.2
---

# 🛡️ CyberSec MCP Multi-Agent Security Stack

A **modular, AI-agent-driven cybersecurity platform** built with MCP (Model Context Protocol) and Gradio, featuring four specialized agents that work together to provide comprehensive security analysis, threat modeling, and incident response.

## 🎯 Agent Stack Overview

The system implements **four specialized security agents** that can operate independently or collaborate through an orchestration layer:

### 1. 🗺️ **Systems Cartographer**
Maps complex systems (infrastructure, codebases, networks) into clear dependency graphs and narratives.
- Obsessed with feedback loops, dependencies, and failure modes
- Always asks: *"What happens if this node dies?"*
- **Tools**: `map_system`, `analyze_blast_radius`

### 2. 🎯 **Red-Teamed Architect**
Designs systems as if an attacker already lives inside them.
- Threat-models every feature with assume-breach mindset
- Identifies attack paths, lateral movement, and privilege escalation routes
- Suggests minimal, enforced security boundaries
- **Tools**: `threat_model_system`, `assume_breach`

### 3. 📊 **Signal Distiller**
Lives in log streams, metrics, and event firehoses.
- Strips noise, surfaces patterns, auto-detects anomalies
- Obsessed with baselines and *"what changed in the last 24 hours"*
- Correlates security events to identify attack chains
- **Tools**: `analyze_logs`, `detect_anomalies`, `correlate_security_events`

### 4. 📋 **On-Call Strategist**
Thinks in runbooks, failure trees, and incident timelines.
- Writes and updates incident response playbooks
- Simulates outages and failure cascades
- Suggests disaster recovery drills
- Calm, procedural, never dramatic
- **Tools**: `create_incident_runbook`, `simulate_component_failure`, `suggest_security_drills`

### 🔄 **Agent Orchestrator**
Coordinates the multi-agent stack, routing tasks and combining outputs.
- **Tool**: `full_security_assessment` - runs complete analysis using all agents

---

## 🚀 Quick Start

### Run Locally

```bash
pip install -r requirements.txt
python app.py
```

Open browser at **http://localhost:7860**

### Deploy on Hugging Face Spaces

1. Push this repository to a new Hugging Face Space
2. Select **Gradio SDK** (version 5.33.2+)
3. The Space will launch automatically

---

## 📖 Usage Examples

### Full Security Assessment
```python
# Analyze entire system with all agents
target = "web_app"  # or "network"
result = full_security_assessment(target)
```

**Output**: Complete security posture including system map, threat model, failure simulations, and risk score.

### Systems Cartographer
```python
# Map a web application
system_map = map_system("web_app")
# Analyze what happens if database fails
blast_radius = analyze_blast_radius("main_db")
```

**Use Cases**:
- Attack surface mapping
- Dependency analysis
- Single point of failure identification
- Cascading failure prediction

### Red-Teamed Architect
```python
# Generate threat model
threats = threat_model_system("web_app")
# Simulate attacker compromising frontend
attack_paths = assume_breach("frontend", "web_app")
```

**Use Cases**:
- Threat modeling for new features
- Assume-breach security reviews
- Trust boundary analysis
- Lateral movement path identification

### Signal Distiller
```python
# Analyze logs for anomalies
log_data = """
ERROR: Authentication failed for user admin
WARNING: Multiple login attempts from 1.2.3.4
ERROR: Authorization bypass attempt detected
"""
analysis = analyze_logs(log_data, "24h")

# Detect metric anomalies
metrics = {"failed_logins": 150, "cpu_usage": 95}
anomalies = detect_anomalies(metrics)

# Correlate security events
events = [
    {"timestamp": "2024-01-01T10:00:00", "source_ip": "1.2.3.4", "event": "login_attempt"},
    {"timestamp": "2024-01-01T10:01:00", "source_ip": "1.2.3.4", "event": "failed_login"},
    {"timestamp": "2024-01-01T10:02:00", "source_ip": "1.2.3.4", "event": "successful_login"}
]
incident_chains = correlate_security_events(events)
```

**Use Cases**:
- Security event analysis
- Anomaly detection
- Attack chain identification
- Baseline establishment

### On-Call Strategist
```python
# Create incident response runbook
runbook = create_incident_runbook("database breach", severity="critical")

# Simulate component failure
impact = simulate_component_failure("api_gateway", "web_app")

# Generate drill scenarios
drills = suggest_security_drills("web_app")
```

**Use Cases**:
- Incident response preparation
- Disaster recovery planning
- Tabletop exercise design
- Post-incident learning

---

## 🏗️ Project Structure

```
cYBERsECmcp/
├── app.py                 # Gradio UI with multi-agent interface
├── app/
│   ├── __init__.py
│   ├── agents.py         # Four specialized security agents
│   ├── server.py         # MCP server configuration
│   ├── tools.py          # MCP tool registration
│   ├── lifespan.py       # Lifecycle management
│   └── context.py        # Application context
├── fake_database.py      # Mock database interface
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

---

## 🔧 Extending the Agent Stack

### Adding New Agents

1. **Define the agent class** in `app/agents.py`:
```python
class MyNewAgent:
    def analyze_something(self, target: str) -> Dict[str, Any]:
        # Your agent logic here
        return {"result": "analysis"}
```

2. **Register MCP tools** in `app/tools.py`:
```python
@mcp.tool()
def my_agent_tool(target: str) -> str:
    agent = MyNewAgent()
    result = agent.analyze_something(target)
    return json.dumps(result, indent=2)
```

3. **Add UI components** in `app.py`:
```python
with gr.Tab("🔮 My New Agent"):
    # Add Gradio components
    pass
```

### Combining Agents

Agents can be combined into **"agent stacks"** for specific use cases:

**Example: Security Review Stack**
- Red-Teamed Architect (threat modeling)
- Systems Cartographer (dependency mapping)
- On-Call Strategist (incident preparation)

**Example: SOC Operations Stack**
- Signal Distiller (log analysis)
- Red-Teamed Architect (attack path detection)
- On-Call Strategist (automated runbook execution)

---

## 🛠️ MCP Tool Reference

### Systems Cartographer Tools
| Tool | Description | Parameters |
|------|-------------|------------|
| `map_system` | Maps system topology | `target`, `config?` |
| `analyze_blast_radius` | Analyzes failure impact | `node_id` |

### Red-Teamed Architect Tools
| Tool | Description | Parameters |
|------|-------------|------------|
| `threat_model_system` | Generates threat model | `target`, `config?` |
| `assume_breach` | Simulates breach scenario | `entry_point`, `target` |

### Signal Distiller Tools
| Tool | Description | Parameters |
|------|-------------|------------|
| `analyze_logs` | Analyzes log patterns | `log_data`, `time_window` |
| `detect_anomalies` | Detects metric anomalies | `metrics` |
| `correlate_security_events` | Correlates events | `events` |

### On-Call Strategist Tools
| Tool | Description | Parameters |
|------|-------------|------------|
| `create_incident_runbook` | Creates runbook | `scenario`, `severity` |
| `simulate_component_failure` | Simulates outage | `component`, `target` |
| `suggest_security_drills` | Suggests drills | `target` |

### Orchestrator Tools
| Tool | Description | Parameters |
|------|-------------|------------|
| `full_security_assessment` | Complete analysis | `target`, `config?` |

---

## 🎓 Design Philosophy

These agents follow the **modular circuit design pattern** - each can be:
- **Plugged into different projects** independently
- **Combined into custom stacks** for specific use cases
- **Extended with new capabilities** without affecting others
- **Replaced or upgraded** individually

### Key Principles
1. **Separation of concerns** - Each agent has one clear purpose
2. **Composability** - Agents work well together and independently
3. **Assume-breach mindset** - Security by default, not afterthought
4. **Operational focus** - Built for real-world incident response
5. **Minimal drama** - Calm, procedural, actionable outputs

---

## 🔒 Security Considerations

This platform is designed for **authorized security testing only**:
- **Pentesting engagements** with proper authorization
- **Purple team exercises** in controlled environments
- **Security research** and vulnerability assessment
- **CTF competitions** and training scenarios

**Not for**:
- Unauthorized access to systems
- Malicious attacks or exploitation
- DoS attacks or destructive actions

---

## 📦 Dependencies

- **FastMCP** - Model Context Protocol server
- **Gradio** - Web UI framework
- **Python 3.8+** - Core runtime

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Additional specialized agents (see the 15 agent personas)
- Real-world tool integrations (nmap, Metasploit, etc.)
- Enhanced threat modeling capabilities
- Machine learning for anomaly detection
- Visualization improvements

---

## 📄 License

Apache 2.0 - See LICENSE file for details.

---

## 🙏 Acknowledgments

Inspired by the **15 modular agent personas** design pattern for pluggable AI systems.

Built with ❤️ for the cybersecurity and AI communities.

---

*Multi-agent security architecture for modern threat landscape.*