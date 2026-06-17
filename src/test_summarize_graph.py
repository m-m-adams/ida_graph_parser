"""Tests for src.summarize_graph using a mocked OpenAI client."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import networkx as nx

from src.summarize_graph import GraphSummarizer


def _make_mock_response(text: str):
    """Build a fake ChatCompletion response object."""
    choice = MagicMock()
    choice.message.content = text
    resp = MagicMock()
    resp.choices = [choice]
    return resp


def _build_summarizer(graph, responses):
    """Create a GraphSummarizer with a mocked LLM that returns *responses* in order."""
    summarizer = GraphSummarizer(graph, api_key="test-key", model="test-model")
    mock_create = MagicMock(side_effect=[_make_mock_response(r) for r in responses])
    summarizer.client.chat.completions.create = mock_create
    return summarizer


class TestLeafNode:
    def test_single_leaf(self):
        G = nx.DiGraph()
        G.add_node("A", instrs=["MOV X0, #1", "RET"], label="func @ A")

        summarizer = _build_summarizer(G, ["Sets X0 to 1 and returns."])
        result = asyncio.run(summarizer.summarize_all())

        assert "A" in result
        assert result["A"] == "Sets X0 to 1 and returns."


class TestNonLeafNode:
    def test_parent_with_one_child(self):
        G = nx.DiGraph()
        G.add_node("A", instrs=["CMP X0, #0", "B.EQ target"], label="func @ A")
        G.add_node("B", instrs=["MOV X0, #1", "RET"], label="func @ B")
        G.add_edge("A", "B", type="intra-function", conditional=True)

        # First call summarizes leaf B, second call summarizes A with B's summary
        summarizer = _build_summarizer(G, [
            "Sets X0 to 1 and returns.",
            "Checks if X0 is zero; if so, branches to a block that sets X0 to 1 and returns.",
        ])
        result = asyncio.run(summarizer.summarize_all())

        assert len(result) == 2
        assert "A" in result
        assert "B" in result


class TestCycleHandling:
    def test_cycle_does_not_infinite_loop(self):
        G = nx.DiGraph()
        G.add_node("A", instrs=["loop_start:"], label="loop @ A")
        G.add_node("B", instrs=["ADD X0, X0, #1"], label="body @ B")
        G.add_edge("A", "B", type="intra-function", conditional=False)
        G.add_edge("B", "A", type="intra-function", conditional=True)

        # B is summarized first (leaf-like since A is in-progress when B tries to recurse back)
        # Then A is summarized with B's summary
        summarizer = _build_summarizer(G, [
            "Increments X0 and loops back.",
            "Loop that increments X0 repeatedly.",
        ])
        result = asyncio.run(summarizer.summarize_all())

        assert "A" in result
        assert "B" in result


class TestDiamondGraph:
    def test_shared_child_summarized_once(self):
        """Diamond: A -> B, A -> C, B -> D, C -> D. D should only be summarized once."""
        G = nx.DiGraph()
        G.add_node("A", instrs=["CMP"], label="A")
        G.add_node("B", instrs=["path1"], label="B")
        G.add_node("C", instrs=["path2"], label="C")
        G.add_node("D", instrs=["RET"], label="D")
        G.add_edge("A", "B", type="intra-function", conditional=True)
        G.add_edge("A", "C", type="intra-function", conditional=True)
        G.add_edge("B", "D", type="intra-function", conditional=False)
        G.add_edge("C", "D", type="intra-function", conditional=False)

        # D summarized once, then B, C, then A = 4 LLM calls
        summarizer = _build_summarizer(G, [
            "Returns.",          # D
            "Path 1 then returns.",  # B
            "Path 2 then returns.",  # C
            "Branches to path 1 or path 2, both return.",  # A
        ])
        result = asyncio.run(summarizer.summarize_all())

        assert len(result) == 4
        # D should have been called exactly once via the mock
        assert summarizer.client.chat.completions.create.call_count == 4
