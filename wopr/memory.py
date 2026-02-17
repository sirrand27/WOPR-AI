"""
Local Joshua AI Agent — Conversation Memory
Sliding window memory with token-aware context management.
"""

import logging
from typing import List, Dict

from config import MAX_CONVERSATION_TURNS, MAX_CONTEXT_TOKENS

logger = logging.getLogger(__name__)


class Memory:
    """Sliding window conversation memory for Ollama context."""

    def __init__(self):
        self.turns: List[Dict[str, str]] = []
        self.task_context: str = ""  # Current task being worked on

    def add_user(self, content: str, source: str = "blackboard"):
        """Add a user/incoming message to memory."""
        self.turns.append({
            "role": "user",
            "content": content,
            "source": source
        })
        self._trim()

    def add_assistant(self, content: str):
        """Add agent's own response to memory."""
        self.turns.append({
            "role": "assistant",
            "content": content
        })
        self._trim()

    def set_task_context(self, context: str):
        """Set the current task context (injected into system prompt)."""
        self.task_context = context

    def clear_task_context(self):
        """Clear task context when task completes."""
        self.task_context = ""

    def get_messages(self) -> List[Dict[str, str]]:
        """Get conversation messages formatted for Ollama API."""
        messages = []
        for turn in self.turns:
            messages.append({
                "role": turn["role"],
                "content": turn["content"]
            })
        return messages

    def get_context_summary(self) -> str:
        """Get a brief summary of current memory state."""
        user_count = sum(1 for t in self.turns if t["role"] == "user")
        asst_count = sum(1 for t in self.turns if t["role"] == "assistant")
        return f"{len(self.turns)} turns ({user_count} user, {asst_count} assistant)"

    def _estimate_tokens(self, text: str) -> int:
        """Rough token estimate (4 chars per token)."""
        return len(text) // 4

    def _total_tokens(self) -> int:
        """Estimate total tokens in memory."""
        return sum(self._estimate_tokens(t["content"]) for t in self.turns)

    def _trim(self):
        """Trim memory to stay within limits."""
        # Trim by turn count
        while len(self.turns) > MAX_CONVERSATION_TURNS:
            removed = self.turns.pop(0)
            logger.debug(f"Trimmed oldest turn ({removed['role']})")

        # Trim by token count
        while self._total_tokens() > MAX_CONTEXT_TOKENS and len(self.turns) > 2:
            removed = self.turns.pop(0)
            logger.debug(f"Trimmed for token limit ({removed['role']})")

    def clear(self):
        """Clear all memory."""
        self.turns.clear()
        self.task_context = ""
        logger.info("Memory cleared")
