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

def gr_query_db():
    return run_tool_sync(mcp.tools["query_db"])

def gr_scan_network(target_ip):
    return run_tool_sync(mcp.tools["scan_network"], target_ip)

def gr_run_exploit(exploit_name, target_ip):
    return run_tool_sync(mcp.tools["run_exploit"], exploit_name, target_ip)


with gr.Blocks(title="CyberSec MCP Server - AI-Powered PenTesting") as demo:
    gr.Markdown("# Cybersecurity Penetration Testing & Purple Team Server")

    with gr.Tab("Query DB"):
        btn_query = gr.Button("Query Database")
        output_query = gr.Textbox(label="DB Query Result")
        btn_query.click(gr_query_db, outputs=output_query)

    with gr.Tab("Network Scan"):
        ip_input = gr.Textbox(label="Target IP")
        btn_scan = gr.Button("Scan Network")
        output_scan = gr.Textbox(label="Scan Result")
        btn_scan.click(gr_scan_network, inputs=ip_input, outputs=output_scan)

    with gr.Tab("Run Exploit"):
        exploit_input = gr.Textbox(label="Exploit Name")
        target_input = gr.Textbox(label="Target IP")
        btn_exploit = gr.Button("Run Exploit")
        output_exploit = gr.Textbox(label="Exploit Result")
        btn_exploit.click(gr_run_exploit, inputs=[exploit_input, target_input], outputs=output_exploit)


if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
