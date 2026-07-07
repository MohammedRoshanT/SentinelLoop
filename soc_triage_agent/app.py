import streamlit as st
import os
import sys
import json
from dotenv import load_dotenv, set_key

# Ensure the multi_tool_agent module can be imported
sys.path.append(os.path.join(os.path.dirname(__file__), "multi_tool_agent"))

from agent import create_agent

# Paths for persistence
env_path = os.path.join(os.path.dirname(__file__), ".env")
history_file = os.path.join(os.path.dirname(__file__), "reports", "chat_history.json")

# Load existing environment variables
load_dotenv(env_path)
saved_api_key = os.getenv("GEMINI_API_KEY", "")

# Functions for chat history persistence
def load_history():
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_history(messages):
    os.makedirs(os.path.dirname(history_file), exist_ok=True)
    with open(history_file, "w") as f:
        json.dump(messages, f)

# Configure Streamlit page
st.set_page_config(
    page_title="SentinelLoop SOC Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for premium aesthetic
st.markdown("""
<style>
    :root {
        --primary-color: #3b82f6;
        --bg-color: #0f172a;
        --card-bg: #1e293b;
    }
    
    .stApp {
        background-color: var(--bg-color);
        color: #f8fafc;
    }
    
    .stSidebar {
        background-color: var(--card-bg) !important;
        border-right: 1px solid #334155;
    }
    
    .main-header {
        font-family: 'Inter', sans-serif;
        background: linear-gradient(90deg, #3b82f6, #8b5cf6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        margin-bottom: 0px;
    }
    
    .sub-header {
        color: #94a3b8;
        font-family: 'Inter', sans-serif;
        font-weight: 400;
        margin-top: -10px;
        margin-bottom: 30px;
    }
    
    /* Chat bubbles */
    .stChatMessage {
        background-color: var(--card-bg);
        border-radius: 12px;
        padding: 1rem;
        margin-bottom: 1rem;
        border: 1px solid #334155;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar Configuration
with st.sidebar:
    st.image("https://www.gstatic.com/devrel-devsite/prod/vc81bb45dd01b0b4a400cc01ce58e8b0a51bc954f9a0d890533f84afcb64bd214/developers/images/touchicon-180.png", width=50)
    st.markdown("### Agent Configuration")
    
    # Text input initialized with saved value
    api_key = st.text_input("Google Gemini API Key", value=saved_api_key, type="password", placeholder="AIzaSy...")
    
    # Save the key to .env if it changes
    if api_key and api_key != saved_api_key:
        set_key(env_path, "GEMINI_API_KEY", api_key)
        saved_api_key = api_key
    
    model_choice = st.selectbox(
        "Select Model",
        options=["gemini-3.5-flash", "gemini-3.1-pro", "gemini-2.5-flash", "gemini-2.0-flash"],
        index=0
    )
    
    st.markdown("---")
    if st.button("Clear Chat History", use_container_width=True):
        st.session_state.messages = []
        save_history([])
        st.rerun()

    st.markdown("---")
    st.markdown("### System Status")
    st.markdown("🟢 FastMCP Server: **Online**")
    st.markdown("🟢 Architecture: **Hybrid (Parallel + Sequential)**")

# Main Chat Interface
st.markdown('<h1 class="main-header">SentinelLoop SOC Triage</h1>', unsafe_allow_html=True)
st.markdown('<h3 class="sub-header">Multi-Agent Automated Threat Analysis Pipeline</h3>', unsafe_allow_html=True)

if "messages" not in st.session_state:
    st.session_state.messages = load_history()

# Display chat messages from history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# React to user input
if prompt := st.chat_input("Enter a security indicator (IP, domain, hash, email)..."):
    if not api_key:
        st.error("⚠️ Please enter your Google Gemini API Key in the sidebar to continue.")
        st.stop()
        
    # Display user message in chat message container
    st.chat_message("user").markdown(prompt)
    st.session_state.messages.append({"role": "user", "content": prompt})
    save_history(st.session_state.messages)
    
    # Initialize the agent dynamically with user config
    try:
        agent = create_agent(api_key=api_key, model_name=model_choice)
    except Exception as e:
        st.error(f"Failed to initialize agent: {e}")
        st.stop()
        
    with st.chat_message("assistant"):
        with st.spinner(f"Agents are analyzing indicator using {model_choice}..."):
            try:
                # Run the agent pipeline using InMemoryRunner
                import asyncio
                from google.adk.runners import InMemoryRunner
                
                runner = InMemoryRunner(agent=agent)
                events = asyncio.run(runner.run_debug(prompt, quiet=True))
                
                # Extract the final output from the last event that has output data
                final_text = ""
                for ev in events:
                    if hasattr(ev, 'data') and ev.data and hasattr(ev.data, 'output'):
                        final_text = ev.data.output
                
                # Check if response is a dict and try to extract the final report
                if isinstance(final_text, dict) and "soc_report" in final_text:
                    final_text = final_text["soc_report"]
                else:
                    final_text = str(final_text)
                    
                st.markdown(final_text)
                st.session_state.messages.append({"role": "assistant", "content": final_text})
                save_history(st.session_state.messages)
            except Exception as e:
                st.error(f"Agent execution failed: {e}")
