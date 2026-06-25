import json

import jsonlines
import asyncio
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import networkx as nx
from tqdm import tqdm

from extract_cfg import extract_cfg_from_db
from llm_interface import LLMInterface
from visualize_cfg import load_cfg, prune_graph


logger = logging.getLogger(__name__)

TITLE_SYSTEM_PROMPT = (
    "You are a reverse-engineering assistant. "
    "You are given a summary of a function's behavior. "
    "Your job is to condense the summary into a concise title "
    "and a one line summary that helps a reverse engineer "
    "understand the function's behavior at a glance. "
    "The title must be human readable and related to the function's behaviour. "
    "Return the title and one line summary as a JSON object."
    "Example output: {\"title\": \"Function XYZ\", \"summary\": \"Does X, Y, and Z\"\\}"
)

class FunctionInfo:
    def __init__(self, name: str, summary: str, title: Optional[str] = None, one_line_summary: Optional[str] = None):
        self.original_name = name
        self.summary = summary
        self.title = title
        self.one_line_summary = one_line_summary

class NameAndCondense:
    def __init__(self, llm_interface: LLMInterface, summaries:dict, output_path: Path):
        self._pbar = None
        self.llm_interface = llm_interface
        self.summaries = summaries
        self.output_path = output_path
        self.functions = dict[str, FunctionInfo]()

    async def process_function(self, func_name: str, func_summary: str):
        user_prompt = "\n\n Name and condense this function: " + func_summary
        while True:
            try:
                title_response = await self.llm_interface.call_llm(TITLE_SYSTEM_PROMPT, user_prompt)
                # Strip markdown code blocks if present
                content = title_response.strip()
                if content.startswith("```"):
                    if content.startswith("```json"):
                        content = content[7:]
                    else:
                        content = content[3:]
                    if content.endswith("```"):
                        content = content[:-3]
                content = content.strip()
                
                parsed = json.loads(content)
                if "title" in parsed and "summary" in parsed:
                    if parsed["title"] == func_name:
                        logging.warning(f"LLM returned original name for function {func_name}, skipping")
                    else:
                        break
                else:
                    logging.error(f"Missing required keys in JSON for function {func_name}: {parsed.keys()}")
            except json.JSONDecodeError:
                logging.error(f"Failed to decode JSON response for function {func_name}: {title_response}")
            except Exception as e:
                logging.error(f"Error calling LLM for function {func_name}: {e}")
                raise e # Simple backoff

        func_info = FunctionInfo(func_name, func_summary, parsed["title"], parsed["summary"])
        self.functions[func_name] = func_info
        with jsonlines.open(self.output_path, "a") as writer:
            writer.write({
                "original_name": func_info.original_name,
                "title": func_info.title,
                "one_line_summary": func_info.one_line_summary
            })

    async def process_functions(self):
        queue = asyncio.Queue()
        for k,v in self.summaries.items():
            queue.put_nowait((k, v))
        self._pbar = tqdm(file=sys.stdout, total=len(self.summaries), desc="Summarizing functions", unit="func")

        async def worker():
            while True:
                try:
                    f = await queue.get()
                    await self.process_function(*f)
                    queue.task_done()
                    self._pbar.update(1)
                except Exception as e:
                    logging.exception(f"Worker encountered an error: {e}")
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.llm_interface.max_concurrent)]
        await queue.join()
        for w in workers:
            w.cancel()

if __name__ == "__main__":
    llm_interface = LLMInterface( base_url="http://192.168.2.80:8000/v1", max_concurrent=32,
                                   model="qwen3-coder-next")
    summaries = dict[str, str]()
    with jsonlines.open("summarized_with_edge_types.json", "r") as reader:
        for line in reader:
            if isinstance(line, dict):
                summaries.update(line)
            else:
                logging.warning(f"Unexpected line format in summaries: {line}")

    name_and_condense = NameAndCondense(llm_interface, summaries, Path("function_titles.jsonl"))
    asyncio.run(name_and_condense.process_functions())
