import streamlit as st
import os
import sys

# Ensure the multi_tool_agent module can be imported
sys.path.append(os.path.join(os.path.dirname(__file__), "multi_tool_agent"))

from agent import create_agent

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
    
    api_key = st.text_input("Google Gemini API Key", type="password", placeholder="AIzaSy...")
    
    model_choice = st.selectbox(
        "Select Model",
        options=["gemini-3.5-flash", "gemini-3.1-pro", "gemini-2.5-flash", "gemini-2.0-flash"],
        index=0
    )
    
    st.markdown("---")
    st.markdown("### System Status")
    st.markdown("🟢 FastMCP Server: **Online**")
    st.markdown("🟢 Architecture: **Hybrid (Parallel + Sequential)**")

# Main Chat Interface
st.markdown('<h1 class="main-header">SentinelLoop SOC Triage</h1>', unsafe_allow_html=True)
st.markdown('<h3 class="sub-header">Multi-Agent Automated Threat Analysis Pipeline</h3>', unsafe_allow_html=True)

if "messages" not in st.session_state:
    st.session_state.messages = []

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
    
    # Initialize the agent dynamically with user config
    try:
        agent = create_agent(api_key=api_key, model_name=model_choice)
    except Exception as e:
        st.error(f"Failed to initialize agent: {e}")
        st.stop()
        
    with st.chat_message("assistant"):
        with st.spinner(f"Agents are analyzing indicator using {model_choice}..."):
            try:
                # Run the agent pipeline
                response = agent.run(prompt)
                
                # Check if response is a dict and try to extract the final report
                if isinstance(response, dict) and "soc_report" in response:
                    final_text = response["soc_report"]
                else:
                    final_text = str(response)
                    
                st.markdown(final_text)
                st.session_state.messages.append({"role": "assistant", "content": final_text})
            except Exception as e:
                st.error(f"Agent execution failed: {e}")
