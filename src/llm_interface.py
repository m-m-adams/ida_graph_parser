import asyncio
import os
import time
from typing import Optional

from openai import AsyncOpenAI

DEFAULT_MODEL = "qwen3-coder-next"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"

class LLMInterface:
    """Handles communication with the LLM API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        max_concurrent: int = 10,
        use_ollama: bool = False,
    ):
        if use_ollama:
            base_url = base_url or os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_BASE_URL)
            if not base_url.rstrip("/").endswith("/v1"):
                base_url = base_url.rstrip("/") + "/v1"
            api_key = api_key or "ollama"
            model = model if model != DEFAULT_MODEL else "short-context-model"
        self.model = model
        self.client = AsyncOpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY", "unused"),
            base_url=base_url or os.environ.get("OPENAI_BASE_URL"),
        )
        self.max_concurrent = max_concurrent
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._active_requests = 0

    def _ensure_semaphore(self):
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)

    async def call_llm(self, system: str, user: str) -> str:
        """Send an async chat completion request, limited by semaphore."""
        self._ensure_semaphore()
        async with self._semaphore:
            self._active_requests += 1
            start = time.perf_counter()
            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
                return response.choices[0].message.content.strip()
            finally:
                elapsed = time.perf_counter() - start
                self._active_requests -= 1
