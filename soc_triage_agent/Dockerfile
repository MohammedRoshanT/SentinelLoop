FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Start the MCP server using FastMCP and the ADK Agent (which usually runs web UI on 8000)
# But since VexScan is 8003, Phexor 8001, we will just use ADK CLI for now or if web UI is needed, we map 8000
CMD ["uv", "run", "adk", "web"]
