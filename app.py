import gradio as gr
import asyncio
from app.server import create_mcp_server


mcp = create_mcp_server()

def run_tool_sync(tool_func, *args):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(tool_func(*args))
    loop.close()
    return result

# Legacy tools
def gr_query_db():
    return run_tool_sync(mcp.tools["query_db"])

def gr_scan_network(target_ip):
    return run_tool_sync(mcp.tools["scan_network"], target_ip)

def gr_run_exploit(exploit_name, target_ip):
    return run_tool_sync(mcp.tools["run_exploit"], exploit_name, target_ip)

# Agent Stack tools
def gr_map_system(target, config):
    return run_tool_sync(mcp.tools["map_system"], target, config if config else None)

def gr_analyze_blast_radius(node_id):
    return run_tool_sync(mcp.tools["analyze_blast_radius"], node_id)

def gr_threat_model(target, config):
    return run_tool_sync(mcp.tools["threat_model_system"], target, config if config else None)

def gr_assume_breach(entry_point, target):
    return run_tool_sync(mcp.tools["assume_breach"], entry_point, target)

def gr_analyze_logs(log_data, time_window):
    return run_tool_sync(mcp.tools["analyze_logs"], log_data, time_window)

def gr_detect_anomalies(metrics):
    return run_tool_sync(mcp.tools["detect_anomalies"], metrics)

def gr_correlate_events(events):
    return run_tool_sync(mcp.tools["correlate_security_events"], events)

def gr_create_runbook(scenario, severity):
    return run_tool_sync(mcp.tools["create_incident_runbook"], scenario, severity)

def gr_simulate_failure(component, target):
    return run_tool_sync(mcp.tools["simulate_component_failure"], component, target)

def gr_suggest_drills(target):
    return run_tool_sync(mcp.tools["suggest_security_drills"], target)

def gr_full_assessment(target, config):
    return run_tool_sync(mcp.tools["full_security_assessment"], target, config if config else None)


with gr.Blocks(title="CyberSec MCP Server - Multi-Agent Security Stack", theme=gr.themes.Monochrome()) as demo:
    gr.Markdown("""
    # 🛡️ Cybersecurity Multi-Agent Security Stack

    **Modular AI agents for penetration testing, threat modeling, and incident response**

    Four specialized agents working together:
    - 🗺️ **Systems Cartographer** - Maps attack surfaces and dependencies
    - 🎯 **Red-Teamed Architect** - Assumes breach, finds attack paths
    - 📊 **Signal Distiller** - Analyzes logs and detects anomalies
    - 📋 **On-Call Strategist** - Creates runbooks and simulates failures
    """)

    with gr.Tab("🎯 Full Security Assessment"):
        gr.Markdown("### Complete security analysis using all agents")

        with gr.Row():
            assess_target = gr.Textbox(
                label="Target System",
                placeholder="web_app, network, or custom",
                value="web_app"
            )
            assess_config = gr.Textbox(
                label="Config (Optional JSON)",
                placeholder='{"custom": "config"}',
                lines=3
            )

        btn_assess = gr.Button("🔍 Run Full Assessment", variant="primary", size="lg")
        output_assess = gr.Textbox(label="Security Assessment", lines=20)

        btn_assess.click(
            gr_full_assessment,
            inputs=[assess_target, assess_config],
            outputs=output_assess
        )

    with gr.Tab("🗺️ Systems Cartographer"):
        gr.Markdown("### Map systems, identify dependencies and failure modes")

        with gr.Accordion("Map System", open=True):
            with gr.Row():
                map_target = gr.Textbox(
                    label="Target",
                    placeholder="web_app, network, api_service",
                    value="web_app"
                )
                map_config = gr.Textbox(
                    label="Config (Optional)",
                    placeholder='{"key": "value"}'
                )
            btn_map = gr.Button("🗺️ Map System")
            output_map = gr.Textbox(label="System Map", lines=15)
            btn_map.click(gr_map_system, inputs=[map_target, map_config], outputs=output_map)

        with gr.Accordion("Analyze Blast Radius"):
            blast_node = gr.Textbox(
                label="Node ID",
                placeholder="e.g., main_db, api_gateway",
                value="main_db"
            )
            btn_blast = gr.Button("💥 Analyze Impact")
            output_blast = gr.Textbox(label="Blast Radius Analysis", lines=10)
            btn_blast.click(gr_analyze_blast_radius, inputs=blast_node, outputs=output_blast)

    with gr.Tab("🎯 Red-Teamed Architect"):
        gr.Markdown("### Threat modeling with assume-breach mindset")

        with gr.Accordion("Threat Model", open=True):
            with gr.Row():
                threat_target = gr.Textbox(label="Target", value="web_app")
                threat_config = gr.Textbox(label="Config (Optional)", placeholder="{}")
            btn_threat = gr.Button("🎯 Generate Threat Model")
            output_threat = gr.Textbox(label="Threat Model", lines=15)
            btn_threat.click(gr_threat_model, inputs=[threat_target, threat_config], outputs=output_threat)

        with gr.Accordion("Assume Breach Analysis"):
            with gr.Row():
                breach_entry = gr.Textbox(label="Entry Point", placeholder="frontend, api_gateway", value="frontend")
                breach_target = gr.Textbox(label="Target System", value="web_app")
            btn_breach = gr.Button("🔓 Simulate Breach")
            output_breach = gr.Textbox(label="Attack Path Analysis", lines=10)
            btn_breach.click(gr_assume_breach, inputs=[breach_entry, breach_target], outputs=output_breach)

    with gr.Tab("📊 Signal Distiller"):
        gr.Markdown("### Analyze logs, detect anomalies, correlate events")

        with gr.Accordion("Log Analysis", open=True):
            log_input = gr.Textbox(
                label="Log Data (one per line or JSON array)",
                placeholder="ERROR: Authentication failed for user admin\nWARNING: Multiple login attempts detected",
                lines=5
            )
            time_window = gr.Textbox(label="Time Window", value="24h")
            btn_logs = gr.Button("📊 Analyze Logs")
            output_logs = gr.Textbox(label="Log Analysis", lines=10)
            btn_logs.click(gr_analyze_logs, inputs=[log_input, time_window], outputs=output_logs)

        with gr.Accordion("Anomaly Detection"):
            metrics_input = gr.Textbox(
                label="Metrics (JSON)",
                placeholder='{"cpu_usage": 95, "failed_logins": 150, "response_time_ms": 3000}',
                lines=3
            )
            btn_anomaly = gr.Button("🔍 Detect Anomalies")
            output_anomaly = gr.Textbox(label="Anomaly Report", lines=10)
            btn_anomaly.click(gr_detect_anomalies, inputs=metrics_input, outputs=output_anomaly)

        with gr.Accordion("Event Correlation"):
            events_input = gr.Textbox(
                label="Events (JSON array)",
                placeholder='[{"timestamp": "2024-01-01T10:00:00", "source_ip": "1.2.3.4", "event": "login_attempt"}]',
                lines=5
            )
            btn_correlate = gr.Button("🔗 Correlate Events")
            output_correlate = gr.Textbox(label="Incident Chains", lines=10)
            btn_correlate.click(gr_correlate_events, inputs=events_input, outputs=output_correlate)

    with gr.Tab("📋 On-Call Strategist"):
        gr.Markdown("### Incident response runbooks and disaster recovery")

        with gr.Accordion("Create Runbook", open=True):
            with gr.Row():
                runbook_scenario = gr.Textbox(
                    label="Scenario",
                    placeholder="database breach, API outage, ransomware attack",
                    value="database breach"
                )
                runbook_severity = gr.Dropdown(
                    label="Severity",
                    choices=["critical", "high", "medium", "low"],
                    value="high"
                )
            btn_runbook = gr.Button("📋 Create Runbook")
            output_runbook = gr.Textbox(label="Incident Runbook", lines=15)
            btn_runbook.click(gr_create_runbook, inputs=[runbook_scenario, runbook_severity], outputs=output_runbook)

        with gr.Accordion("Simulate Failure"):
            with gr.Row():
                fail_component = gr.Textbox(label="Component", placeholder="main_db, api_gateway", value="main_db")
                fail_target = gr.Textbox(label="Target System", value="web_app")
            btn_simulate = gr.Button("💣 Simulate Outage")
            output_simulate = gr.Textbox(label="Impact Analysis", lines=10)
            btn_simulate.click(gr_simulate_failure, inputs=[fail_component, fail_target], outputs=output_simulate)

        with gr.Accordion("Security Drills"):
            drill_target = gr.Textbox(label="Target System", value="web_app")
            btn_drills = gr.Button("🎯 Suggest Drills")
            output_drills = gr.Textbox(label="Recommended Drills", lines=15)
            btn_drills.click(gr_suggest_drills, inputs=drill_target, outputs=output_drills)

    with gr.Tab("⚙️ Legacy Tools"):
        gr.Markdown("### Original pentesting tools")

        with gr.Row():
            with gr.Column():
                gr.Markdown("#### Query Database")
                btn_query = gr.Button("Query DB")
                output_query = gr.Textbox(label="Result")
                btn_query.click(gr_query_db, outputs=output_query)

            with gr.Column():
                gr.Markdown("#### Network Scan")
                ip_input = gr.Textbox(label="Target IP")
                btn_scan = gr.Button("Scan")
                output_scan = gr.Textbox(label="Result")
                btn_scan.click(gr_scan_network, inputs=ip_input, outputs=output_scan)

            with gr.Column():
                gr.Markdown("#### Run Exploit")
                exploit_input = gr.Textbox(label="Exploit Name")
                target_input = gr.Textbox(label="Target IP")
                btn_exploit = gr.Button("Execute")
                output_exploit = gr.Textbox(label="Result")
                btn_exploit.click(gr_run_exploit, inputs=[exploit_input, target_input], outputs=output_exploit)

    gr.Markdown("""
    ---
    ### 💡 Quick Start Examples

    **Full Assessment**: Use `web_app` or `network` as target to see all agents in action

    **Systems Cartographer**: Map `web_app` → Get node IDs → Analyze blast radius of `main_db`

    **Red-Teamed Architect**: Threat model `network` → Run assume-breach from `frontend`

    **Signal Distiller**: Paste logs or metrics → Detect patterns and anomalies

    **On-Call Strategist**: Create runbooks → Simulate failures → Generate drill scenarios
    """)


if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
