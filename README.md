---
license: apache-2.0
title: CyberSec MCP Gradio Server
sdk: gradio
emoji: 💻
colorFrom: red
colorTo: gray
short_description: This project implements a pentesting and purple team server
sdk_version: 5.33.2
---

# CyberSec MCP Gradio Server

This project implements a **penetration testing and purple team AI-agent-driven server** built with MCP and a Gradio UI frontend, designed to run as a **Hugging Face Space**.

## Project structure

- `app.py` - Gradio app entrypoint for Hugging Face Spaces.
- `app/` - Python package containing MCP server, lifespan, tools, and context.
- `fake_database.py` - Stub/mock database interface.
- `requirements.txt` - Python dependencies.

## Setup & Run locally

```bash
pip install -r requirements.txt
python app.py
```

Then open your browser at http://localhost:7860

## Deploy on Hugging Face Spaces

- Rename `run.py` to `app.py` (already done).
- Push this repository to a new Hugging Face Space with `Gradio` SDK selected.
- The Space will launch automatically.

## Extending tools

Add or replace functions in `app/tools.py` to implement real scanning, exploitation, and analysis workflows.

## Notes

- The MCP server lifecycle manages DB connections and resource cleanup.
- Gradio provides a clean, tabbed UI for user interaction.
- This setup uses async-to-sync wrappers for tool calls.

---

*Prepared for Cybersecurity AI agent development and purple teaming.*