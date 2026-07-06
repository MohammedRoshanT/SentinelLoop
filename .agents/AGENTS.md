# Agent Workspace Rules

- **Confidence and Grounding**:
  LLM tools and models may sometimes output confident-sounding but ungrounded findings.
  All agents must verify intelligence findings.
  If any findings are of low confidence or indeterminate (e.g., incomplete OSINT profiles, unconfirmed URL redirects, or conflicting reputation votes), the agent must explicitly flag the findings for human review in the final report and ticket note before recommending any blocking or quarantining action.
