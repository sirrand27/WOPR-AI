"""
Blackboard MCP Server — Training Data Utilities
JSONL export and fine-tuning format helpers.
"""

import json


def export_training_jsonl(examples: list[dict]) -> str:
    """Convert training examples to JSONL format (one JSON object per line)."""
    lines = []
    for ex in examples:
        lines.append(json.dumps(ex, separators=(",", ":")))
    return "\n".join(lines)


def format_for_finetuning(example: dict) -> dict:
    """Format a training example into chat-completion fine-tuning format.
    Returns a messages-format dict with system/user/assistant roles."""
    phase = example.get("phase", "unknown")
    category = example.get("category", "unknown")

    system_msg = (
        f"You are TARS, a penetration testing AI agent operating in the {phase} phase. "
        f"You specialize in {category}. You execute non-destructive network assessments "
        f"using standard security tools (nmap, curl, smbclient, etc.) and provide "
        f"professional-grade findings with CVSS scores and remediation guidance."
    )

    user_msg = f"Context: {example.get('context', '')}\n\nWhat should be done next and why?"

    parts = []
    if example.get("reasoning"):
        parts.append(f"Reasoning: {example['reasoning']}")
    if example.get("action"):
        parts.append(f"Action: {example['action']}")
    if example.get("observation"):
        parts.append(f"Observation: {example['observation']}")
    if example.get("conclusion"):
        parts.append(f"Conclusion: {example['conclusion']}")
    assistant_msg = "\n\n".join(parts)

    return {
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": assistant_msg},
        ]
    }


def export_finetuning_jsonl(examples: list[dict]) -> str:
    """Export training examples as fine-tuning JSONL (chat-completion format)."""
    lines = []
    for ex in examples:
        formatted = format_for_finetuning(ex)
        lines.append(json.dumps(formatted, separators=(",", ":")))
    return "\n".join(lines)
