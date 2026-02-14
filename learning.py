"""
Local Joshua AI Agent — Learning Module
Auto-generates training examples from each interaction.
"""

import logging
from typing import List, Optional

from blackboard import BlackboardClient

logger = logging.getLogger(__name__)


class LearningEngine:
    """Auto-generate training examples from agent interactions."""

    def __init__(self, blackboard: BlackboardClient):
        self.blackboard = blackboard
        self._pending: List[dict] = []

    def capture(self, context: str, reasoning: str, action: str,
                observation: str = "", conclusion: str = "",
                category: str = "tactical", phase: str = "recon",
                tools_used: Optional[List[str]] = None,
                hosts_involved: Optional[List[str]] = None,
                severity: str = "INFO"):
        """Capture a training example from the current interaction."""
        example = {
            "category": category,
            "phase": phase,
            "context": context,
            "reasoning": reasoning,
            "action": action,
            "observation": observation,
            "conclusion": conclusion,
            "tools_used": tools_used or [],
            "hosts_involved": hosts_involved or [],
            "severity_relevant": severity
        }
        self._pending.append(example)
        logger.info(f"Training example captured: {category}/{phase} — {context[:60]}")

    def flush(self):
        """Submit all pending training examples to Blackboard."""
        submitted = 0
        for example in self._pending:
            result = self.blackboard.submit_training_example(**example)
            if result:
                submitted += 1
            else:
                logger.warning(f"Failed to submit training example: {example['context'][:50]}")

        count = len(self._pending)
        self._pending.clear()
        logger.info(f"Flushed {submitted}/{count} training examples to Blackboard")
        return submitted

    def capture_tool_interaction(self, tool_name: str, tool_args: dict,
                                  tool_output: str, user_query: str,
                                  agent_analysis: str):
        """Convenience method to capture a tool-based interaction."""
        # Determine category based on tool
        tool_categories = {
            "sherlock": ("reconnaissance", "recon"),
            "theharvester": ("reconnaissance", "recon"),
            "whatweb": ("reconnaissance", "enum"),
            "fierce": ("reconnaissance", "recon"),
            "dnsrecon": ("reconnaissance", "recon"),
            "photon": ("reconnaissance", "enum"),
            "h8mail": ("tactical", "deep_enum"),
            "court_records": ("tactical", "deep_enum"),
            "court_case": ("analysis", "deep_enum"),
        }
        category, phase = tool_categories.get(tool_name, ("tactical", "recon"))

        # Build context without specific target details (anti-hallucination)
        args_desc = ", ".join(f"{k}=<target>" for k in tool_args.keys())

        self.capture(
            context=f"Operator requested {tool_name} analysis. Query: {user_query[:100]}",
            reasoning=f"Selected {tool_name} as the appropriate tool for this investigation type.",
            action=f"{tool_name}({args_desc})",
            observation=self._generalize_observation(tool_output[:500]),
            conclusion=agent_analysis[:300] if agent_analysis else "",
            category=category,
            phase=phase,
            tools_used=[tool_name],
            severity="INFO"
        )

    def _generalize_observation(self, raw_output: str) -> str:
        """Generalize tool output for training (anti-hallucination rule)."""
        # Keep structure, remove specific PII/data
        if not raw_output:
            return "Tool returned no significant results."

        lines = raw_output.split("\n")
        if len(lines) > 10:
            return f"Tool returned {len(lines)} lines of output with multiple data points."
        return f"Tool returned results ({len(raw_output)} chars)."

    @property
    def pending_count(self):
        return len(self._pending)
