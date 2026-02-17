"""
Local Joshua AI Agent — Learning Module
Auto-generates training examples from each interaction.
Includes TrainingPipeline for fine-tuning loop closure.
"""

import json
import logging
import os
from datetime import datetime, timezone
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


class TrainingPipeline:
    """Export → Adapt → Train pipeline for W.O.P.R. fine-tuning.

    Stages:
    1. Export training data from Blackboard → JSONL
    2. Adapt system messages from generic to W.O.P.R. persona
    3. Train (manual or automated LoRA fine-tune)
    4. Swap model in Ollama config
    """

    def __init__(self, blackboard):
        from config import (TRAINING_DATA_DIR, MIN_TRAINING_EXAMPLES,
                           SYSTEM_PROMPT, AGENT_NAME)
        self.blackboard = blackboard
        self.data_dir = TRAINING_DATA_DIR
        self.min_examples = MIN_TRAINING_EXAMPLES
        self.system_prompt = SYSTEM_PROMPT
        self.agent_name = AGENT_NAME
        os.makedirs(self.data_dir, exist_ok=True)

    def export_training_data(self):
        """Export training examples from Blackboard to JSONL file.
        Returns (filepath, count) or (None, 0) on failure."""
        try:
            result = self.blackboard._mcp_call("get_training_data", {
                "format": "finetuning"
            })
        except Exception as e:
            logger.error(f"Training data export failed: {e}")
            return None, 0

        if not result:
            logger.warning("No training data returned from Blackboard")
            return None, 0

        # result should be a list of training examples
        examples = result if isinstance(result, list) else result.get("examples", [])

        if len(examples) < self.min_examples:
            logger.info(f"Only {len(examples)} examples (need {self.min_examples}). Skipping export.")
            return None, len(examples)

        # Write JSONL
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.data_dir, f"wopr_training_{timestamp}.jsonl")

        count = 0
        with open(filepath, "w", encoding="utf-8") as f:
            for ex in examples:
                adapted = self._adapt_example(ex)
                if adapted:
                    f.write(json.dumps(adapted, ensure_ascii=False) + "\n")
                    count += 1

        logger.info(f"Exported {count} training examples to {filepath}")
        return filepath, count

    def _adapt_example(self, example):
        """Rewrite a training example with W.O.P.R. system prompt and persona."""
        if not isinstance(example, dict):
            return None

        # Build conversation format for fine-tuning
        context = example.get("context", "")
        reasoning = example.get("reasoning", "")
        action = example.get("action", "")
        observation = example.get("observation", "")
        conclusion = example.get("conclusion", "")

        # Construct user message (the query/situation)
        user_msg = context
        if not user_msg:
            return None

        # Construct assistant response (what WOPR should say)
        parts = []
        if reasoning:
            parts.append(reasoning)
        if action:
            parts.append(f"Action: {action}")
        if observation:
            parts.append(observation)
        if conclusion:
            parts.append(conclusion)
        assistant_msg = " ".join(parts)

        if not assistant_msg:
            return None

        return {
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_msg},
                {"role": "assistant", "content": assistant_msg},
            ]
        }

    def get_status(self):
        """Get training pipeline status."""
        files = []
        if os.path.isdir(self.data_dir):
            files = [f for f in os.listdir(self.data_dir) if f.endswith(".jsonl")]

        total_examples = 0
        for f in files:
            path = os.path.join(self.data_dir, f)
            with open(path) as fh:
                total_examples += sum(1 for _ in fh)

        return {
            "data_dir": self.data_dir,
            "export_files": len(files),
            "total_examples": total_examples,
            "min_required": self.min_examples,
            "ready_to_train": total_examples >= self.min_examples,
        }
