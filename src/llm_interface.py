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

def get_summary(system:str, text: str) -> str:
    """Call the LLM to get a summary of the given text."""
    llm_interface = LLMInterface(
        api_key="",
        base_url="http://192.168.1.101:8000/v1",
        model=DEFAULT_MODEL,
        max_concurrent=10,
    )
    return asyncio.run(llm_interface.call_llm(system=system, user=text))

def naive_summarizer():
    import ida_domain
    FUNC_SYSTEM_PROMPT = (
        "You are a reverse-engineering assistant. "
        "You are given a single function's aarch64 assembly. "
        "Summarize what this function does. Be concise. "
        "Your audience is an expert reverse engineer. "
        "If a function follows standard ABI calling conventions don't reexplain them."
    )

    db_path = "/Users/mark/windows_share/test/reorder_and_pad.exe.i64"
    with ida_domain.Database.open(db_path, save_on_close=False) as db:
        main_func = db.functions.get_by_name("sub_140001234")
        instrs = [db.instructions.get_disassembly(instr) for instr in db.functions.get_instructions(main_func)]
        text = "\n".join(instrs)
        print(get_summary(FUNC_SYSTEM_PROMPT, text))


if __name__ == "__main__":
    SYSTEM_PROMPT = """
    You are a reverse-engineering assistant. 
    You are given a list of functions and their summaries.
    You're job is to accurately describe the overall behaviour of the program.
    Focus on the execution path - the entrypoint is ExReleaseFastMutexUnsafeAndLeaveCriticalRegion
    and the user main function is windows::main(). Your summary should be based on what happens when the
    program is run. 
    """
    with open("../data/function_summaries.jsonl", "r") as f:
        summaries = f.read()
    print(get_summary(SYSTEM_PROMPT, summaries))

