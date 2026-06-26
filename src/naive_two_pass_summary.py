import networkx as nx
import matplotlib.pyplot as plt
from ipysigma import Sigma
import numpy as np
from collections import defaultdict
import ollama
from tqdm import tqdm
import asyncio
import json
import time

from src.visualize_cfg import load_cfg
from src.community_detection import collapse_leiden


MODEL = "qwen3-coder-next"
# BASE_URL = "http://100.104.79.110:11434"  # tailscale
BASE_URL = "http://192.168.1.101:8000"      # spark
BATCH_SIZE = 8
MAX_CONCURRENT = 8  # Explicit semaphore limit
MAX_ASSEMBLY_CHARS = 4000  # Truncate long assembly code

FUNC_SYSTEM_PROMPT = (
    "You are a reverse-engineering assistant analyzing obfuscated control flow. "
    "You are given a chunk of aarch64 assembly organized into basic blocks, "
    "along with the control flow between them. "
    "This chunk may represent: a single complete function, part of a function, "
    "a mixture of partial functions, or obfuscated control flow from multiple sources. "
    "Summarize what this chunk of code does, referencing specific basic blocks by their labels. "
    "Be concise and specific. Your audience is an expert reverse engineer. "
    "If a function follows standard ABI calling conventions don't reexplain them."
)

INTEGRATE_NEIGHBORS_SYSTEM_PROMPT = (
    "You are a reverse-engineering assistant analyzing obfuscated control flow. "
    "You are given a chunk of aarch64 assembly organized into basic blocks, "
    "along with the control flow between them. "
    "This chunk may represent: a single complete function, part of a function, "
    "a mixture of partial functions, or obfuscated control flow from multiple sources. "
    "You are also given summaries of neighboring blocks, categorized as:\n"
    "- PARENTS: Blocks that call or branch to this chunk\n"
    "- CHILDREN: Blocks that this chunk calls or branches to\n"
    "Integrate these neighboring block summaries into your understanding of this chunk. "
    "Summarize what this chunk of code does, referencing specific basic blocks by their labels. "
    "Focus on how the children blocks are used and how this chunk fits into the parents' workflows. "
    "Focus on how inputs are used and transformed into outputs within and across these blocks. "
    "Be concise and specific. Your audience is an expert reverse engineer. "
    "If a function follows standard ABI calling conventions don't reexplain them."
)

client = ollama.Client(host=BASE_URL)
semaphore = asyncio.Semaphore(MAX_CONCURRENT)


def generate(prompt, system_prompt=None):
    """Generate text from prompt using Ollama"""
    full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
    try:
        response = client.generate(
            model=MODEL, 
            prompt=full_prompt, 
            stream=False
        )
        return response["response"]
    except Exception as e:
        return f"[ERROR: {str(e)}]"


async def async_generate(prompt, system_prompt=None):
    """Async wrapper with semaphore to limit concurrent requests"""
    async with semaphore:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, generate, prompt, system_prompt)

# Load graph
G = load_cfg('parsed_xref_graph.json')

# Aggregate Communities
G_communities, community_list = collapse_leiden(G, resolution=0.001)


def format_neighbor_summary(neighbor, summary, edge_type):
    """Format a neighbor's summary with edge type"""
    return f"[{edge_type}] {neighbor}:\n{summary}"


async def run_pass_1():
    """Pass 1: Summarize nodes standalone in parallel batches"""
    print("=== PASS 1: Standalone Summaries ===")
    nodes = list(G_communities.nodes())
    start_time = time.time()
    
    # Process in batches
    for i in tqdm(range(0, len(nodes), BATCH_SIZE), desc="Pass 1 batches", total=(len(nodes) + BATCH_SIZE - 1) // BATCH_SIZE):
        batch = nodes[i:i + BATCH_SIZE]
        batch_start = time.time()
        
        tasks = [
            async_generate(G_communities.nodes[node]['subgraph_json'], system_prompt=FUNC_SYSTEM_PROMPT)
            for node in batch
        ]
        results = await asyncio.gather(*tasks)
        
        batch_time = time.time() - batch_start
        for node, summary in zip(batch, results):
            G_communities.nodes[node]['summary'] = summary
        
        avg_per_node = batch_time / len(batch)
        tqdm.write(f"  Batch of {len(batch)}: {batch_time:.2f}s ({avg_per_node:.2f}s per node)")
    
    elapsed = time.time() - start_time
    print(f"Completed Pass 1: {len(G_communities.nodes())} nodes summarized in {elapsed:.2f}s")


def prepare_pass2_prompt(node):
    """Prepare a full prompt for Pass 2 for a given node"""
    assembly_text = G_communities.nodes[node]['subgraph_json']
    
    # Truncate assembly if too large
    if len(assembly_text) > MAX_ASSEMBLY_CHARS:
        assembly_text = assembly_text[:MAX_ASSEMBLY_CHARS] + "\n... (truncated)"
    
    # Get parents (predecessors) and children (successors)
    parents = list(G_communities.predecessors(node))
    children = list(G_communities.successors(node))
    
    # Format parent summaries
    parents_text = ""
    if parents:
        parents_text = "PARENTS (call or branch to this function):\n"
        for parent in parents:
            if 'summary' in G_communities.nodes[parent]:
                edge_type = G_communities[parent][node].get('type', 'unknown')
                parents_text += format_neighbor_summary(parent, G_communities.nodes[parent]['summary'], edge_type) + "\n"
    
    # Format child summaries
    children_text = ""
    if children:
        children_text = "CHILDREN (this assembly calls or branches to):\n"
        for child in children:
            if 'summary' in G_communities.nodes[child]:
                edge_type = G_communities[node][child].get('type', 'unknown')
                children_text += format_neighbor_summary(child, G_communities.nodes[child]['summary'], edge_type) + "\n"
    
    # Combine into full prompt
    neighbors_context = ""
    if parents_text or children_text:
        neighbors_context = f"\n{parents_text}{children_text}"
    
    return f"{assembly_text}{neighbors_context}"


async def run_pass_2():
    """Pass 2: Create contextual summaries in parallel batches"""
    print("\n=== PASS 2: Contextual Summaries with Neighbors ===")
    nodes = list(G_communities.nodes())
    start_time = time.time()
    
    # Process in batches
    for i in tqdm(range(0, len(nodes), BATCH_SIZE), desc="Pass 2 batches", total=(len(nodes) + BATCH_SIZE - 1) // BATCH_SIZE):
        batch = nodes[i:i + BATCH_SIZE]
        batch_start = time.time()
        
        tasks = [
            async_generate(prepare_pass2_prompt(node), system_prompt=INTEGRATE_NEIGHBORS_SYSTEM_PROMPT)
            for node in batch
        ]
        results = await asyncio.gather(*tasks)
        
        batch_time = time.time() - batch_start
        for node, contextual_summary in zip(batch, results):
            G_communities.nodes[node]['contextual_summary'] = contextual_summary
        
        avg_per_node = batch_time / len(batch)
        tqdm.write(f"  Batch of {len(batch)}: {batch_time:.2f}s ({avg_per_node:.2f}s per node)")
    
    elapsed = time.time() - start_time
    print(f"Completed Pass 2: {len(G_communities.nodes())} contextual summaries created in {elapsed:.2f}s")


async def main():
    """Run both passes"""
    total_start = time.time()
    
    print(f"Starting with {len(G_communities.nodes())} nodes")
    print(f"Batch size: {BATCH_SIZE}, Max concurrent: {MAX_CONCURRENT}")
    print(f"Model: {MODEL} on {BASE_URL}\n")
    
    await run_pass_1()
    await run_pass_2()
    
    # Save summaries
    summaries = {
        node: {
            'summary': G_communities.nodes[node].get('summary', ''),
            'contextual_summary': G_communities.nodes[node].get('contextual_summary', '')
        }
        for node in G_communities.nodes()
    }
    
    with open('two_pass_summaries.json', 'w') as f:
        json.dump(summaries, f, indent=2)
    
    total_time = time.time() - total_start
    print(f"\n=== SUMMARY ===")
    print(f"Total time: {total_time:.2f}s ({total_time/60:.1f}m)")
    print(f"Avg time per node: {total_time / len(G_communities.nodes()):.2f}s")
    print(f"Saved summaries to two_pass_summaries.json")


if __name__ == "__main__":
    asyncio.run(main()) 




