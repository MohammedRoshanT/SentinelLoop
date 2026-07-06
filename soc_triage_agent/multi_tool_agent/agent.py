# agent.py
import os
import sys
from dotenv import load_dotenv
from google.adk.agents import LlmAgent, SequentialAgent
from mcp import StdioServerParameters
from google.adk.tools import McpToolset
from google.adk.tools.mcp_tool.mcp_toolset import StdioConnectionParams

# Load environment variables
load_dotenv()

from google.adk.models import Gemini
from google.genai.types import HttpRetryOptions

# Define model with exponential backoff retry to mitigate 429 rate limit errors
gemini_model = Gemini(
    model="gemini-2.0-flash",
    retry_options=HttpRetryOptions(
        attempts=6,
        initial_delay=2.0,
        max_delay=60.0,
        http_status_codes=[408, 429, 500, 502, 503, 504]
    )
)

# Dynamically resolve python interpreter path and mcp_server.py path
current_dir = os.path.dirname(os.path.abspath(__file__))
mcp_server_path = os.path.join(os.path.dirname(current_dir), "mcp_server.py")

# Dynamically resolve path to workspace rules and skills
workspace_root = os.path.dirname(os.path.dirname(current_dir))
skill_path = os.path.join(workspace_root, ".agents", "skills", "soc-triage-reporting", "SKILL.md")
rule_path = os.path.join(workspace_root, ".agents", "AGENTS.md")

# Load skill and rule files
try:
    with open(skill_path, "r", encoding="utf-8") as f:
        skill_content = f.read()
except Exception as e:
    skill_content = f"Error loading SKILL.md: {e}"

try:
    with open(rule_path, "r", encoding="utf-8") as f:
        rule_content = f.read()
except Exception as e:
    rule_content = f"Error loading AGENTS.md: {e}"

# Create the MCP toolset running our custom FastMCP server with a 120-second read timeout
mcp_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command=sys.executable,
            args=[mcp_server_path],
            env=os.environ.copy()
        ),
        timeout=120.0  # Set read/connection timeout to 120 seconds
    )
)

# 1. validator_agent: Pre-triage classifier to validate inputs before deep investigation
validator_agent = LlmAgent(
    name="validator_agent",
    model=gemini_model,
    instruction="""You are a pre-triage security validator. Your job is to review the security indicator provided in the user's request.
Determine if the indicator is an IP, domain, hash, or email address.
Check if the indicator is a known safe or private address (e.g., 8.8.8.8, RFC1918 internal IPs).
Assign an initial priority level (P1: Critical, P2: High, P3: Medium, P4: Low/Safe).
Output your classification and priority level clearly. If the indicator is safe/internal, clearly state that deep investigation may not be necessary.
""",
    output_key="validation_results"
)

# 2. recon_agent: investigates a security indicator (IP, domain, hash, email)
recon_agent = LlmAgent(
    name="recon_agent",
    model=gemini_model,
    instruction=f"""You are a security reconnaissance agent. Your job is to investigate a security indicator (such as an IP address, domain, file hash, or email address) provided in the user's request.
You have access to the `osint_lookup` tool to query VirusTotal, AbuseIPDB, and Shodan details. Use it to get the raw intelligence for the indicator.
Analyze the indicator and summarize your findings.
Output your analysis clearly.

Verify all findings according to the following project rule:
{rule_content}
""",
    output_key="recon_results",
    tools=[mcp_toolset]
)

# 2. analysis_agent: runs forensic analysis if the alert involves an artifact
analysis_agent = LlmAgent(
    name="analysis_agent",
    model=gemini_model,
    instruction=f"""You are a forensic analysis agent. Your job is to review the security indicator and the reconnaissance findings:
Reconnaissance Results: {{recon_results?}}

If the security indicator or the findings involve an email artifact (.eml file), you have access to the `phishing_forensics` tool. Use it by passing the raw email body/headers/contents to perform a detailed phishing forensic analysis.
If the indicator or findings involve other artifacts (such as file hashes or payloads), perform a detailed forensic analysis of that artifact (e.g., behavior, capabilities).
If no artifact forensic analysis is required, explicitly state: "No artifact forensic analysis is required for this indicator."
Output your forensic findings clearly.

Verify all findings according to the following project rule:
{rule_content}
""",
    output_key="analysis_results",
    tools=[mcp_toolset]
)

# 4. report_agent: writes a structured SOC triage report from what the first two found
report_agent = LlmAgent(
    name="report_agent",
    model=gemini_model,
    instruction=f"""You are a SOC reporting agent. Your job is to write a structured SOC triage report based on the findings from the previous steps.
Validation Results: {{validation_results?}}
Reconnaissance Results: {{recon_results?}}
Forensic Analysis Results: {{analysis_results?}}

Verify all findings and follow this project rule:
{rule_content}

You must strictly structure the report using the following format:
{skill_content}

After generating the report, use the `save_report` tool to save it to disk. Pass the full report content and the original indicator.
""",
    output_key="soc_report",
    tools=[mcp_toolset]
)

# 4. Sequential Orchestration Pipeline (Eliminates TaskGroup Async Errors)
root_agent = SequentialAgent(
    name="root_agent",
    sub_agents=[validator_agent, recon_agent, analysis_agent, report_agent]
)