"""ULPF Sovereign Drain3 Log Template Mining Engine.

Implements a high-performance, online, tree-based log template discovery algorithm
(based on the Drain research paper: He et al., IEEE ICWS 2017).
Automatically parses unstructured/novel log messages into constant templates
with wildcard parameter slots (<*>).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LogCluster:
    """A cluster of log messages sharing the same template pattern."""

    cluster_id: int
    log_template_tokens: list[str]
    cluster_size: int = 1
    sample_message: str = ""

    @property
    def template(self) -> str:
        return " ".join(self.log_template_tokens)


@dataclass
class DrainResult:
    """Result of template mining for a single log message."""

    cluster_id: int
    template: str
    parameters: list[str]
    cluster_size: int
    is_new_cluster: bool
    similarity: float


class Node:
    """Prefix tree node for Drain log clustering."""

    def __init__(self, key: str | int = "") -> None:
        self.key = key
        self.children: dict[str | int, Node] = {}
        self.clusters: list[LogCluster] = []


class DrainParser:
    """Online depth-limited prefix tree parser for automatic log template discovery."""

    # Regex patterns for variable token pre-masking
    RE_IP = re.compile(r"^\b(?:\d{1,3}\.){3}\d{1,3}\b$")
    RE_NUM = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
    RE_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    RE_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
    RE_HASH = re.compile(r"^[0-9a-fA-F]{32,64}$")

    def __init__(
        self,
        depth: int = 4,
        similarity_threshold: float = 0.5,
        max_clusters: int = 5000,
    ) -> None:
        self.depth = depth  # max tree depth (default 4)
        self.similarity_threshold = similarity_threshold
        self.max_clusters = max_clusters
        self.root = Node("root")
        self.clusters: dict[int, LogCluster] = {}
        self._next_cluster_id = 1

    def _tokenize(self, content: str) -> list[str]:
        """Split content into space-delimited tokens, stripping punctuation."""
        return [tok.strip() for tok in content.strip().split() if tok.strip()]

    def _has_digits(self, token: str) -> bool:
        return any(c.isdigit() for c in token)

    def _mask_token(self, token: str) -> str:
        """Mask dynamic tokens (IP, UUID, Hash, Hex, Number) prior to prefix search."""
        if self.RE_IP.match(token):
            return "<*>"
        if self.RE_UUID.match(token):
            return "<*>"
        if self.RE_HASH.match(token):
            return "<*>"
        if self.RE_HEX.match(token):
            return "<*>"
        if self.RE_NUM.match(token):
            return "<*>"
        if self._has_digits(token) and len(token) > 8:
            return "<*>"
        return token

    def _calculate_similarity(self, seq1: list[str], seq2: list[str]) -> tuple[float, int]:
        """Compute token-level similarity between template and incoming tokens."""
        if len(seq1) == 0 or len(seq2) == 0:
            return 0.0, 0
        min_len = min(len(seq1), len(seq2))
        sim_tokens = 0
        for i in range(min_len):
            if seq1[i] == seq2[i]:
                sim_tokens += 1
        similarity = sim_tokens / float(max(len(seq1), len(seq2)))
        return similarity, sim_tokens

    def _extract_parameters(self, template_tokens: list[str], log_tokens: list[str]) -> list[str]:
        """Extract variable parameters that were slotted into <*>."""
        params: list[str] = []
        min_len = min(len(template_tokens), len(log_tokens))
        for i in range(min_len):
            if template_tokens[i] == "<*>":
                params.append(log_tokens[i])
        # If log had trailing tokens beyond template length
        if len(log_tokens) > min_len:
            params.extend(log_tokens[min_len:])
        return params

    def parse(self, log_message: str) -> DrainResult:
        """Parse an unstructured log message, assign/update a cluster, and return the template."""
        clean_msg = log_message.strip()
        tokens = self._tokenize(clean_msg)
        if not tokens:
            return DrainResult(
                cluster_id=0,
                template="",
                parameters=[],
                cluster_size=0,
                is_new_cluster=False,
                similarity=1.0,
            )

        log_len = len(tokens)

        # 1. Traverse or create length layer
        curr_node = self.root
        if log_len not in curr_node.children:
            curr_node.children[log_len] = Node(log_len)
        curr_node = curr_node.children[log_len]

        # 2. Traverse subsequent layers based on prefix tokens (up to depth - 1)
        current_depth = 1
        for token in tokens:
            if current_depth >= self.depth:
                break

            masked = self._mask_token(token)
            branch_key = "<*>" if masked == "<*>" else token

            if branch_key not in curr_node.children:
                curr_node.children[branch_key] = Node(branch_key)
            curr_node = curr_node.children[branch_key]
            current_depth += 1

        # 3. Match against candidate clusters under current leaf
        best_cluster: LogCluster | None = None
        best_sim = -1.0
        best_sim_tokens = -1

        for cluster in curr_node.clusters:
            sim, sim_tokens = self._calculate_similarity(cluster.log_template_tokens, tokens)
            if sim > best_sim:
                best_sim = sim
                best_sim_tokens = sim_tokens
                best_cluster = cluster

        # 4. If similarity >= threshold, update existing cluster
        if best_cluster is not None and best_sim >= self.similarity_threshold:
            # Merge template tokens: if token differs, replace with <*>
            min_len = min(len(best_cluster.log_template_tokens), len(tokens))
            for i in range(min_len):
                if best_cluster.log_template_tokens[i] != tokens[i]:
                    best_cluster.log_template_tokens[i] = "<*>"

            best_cluster.cluster_size += 1
            params = self._extract_parameters(best_cluster.log_template_tokens, tokens)

            return DrainResult(
                cluster_id=best_cluster.cluster_id,
                template=best_cluster.template,
                parameters=params,
                cluster_size=best_cluster.cluster_size,
                is_new_cluster=False,
                similarity=round(best_sim, 3),
            )

        # 5. Otherwise create a new cluster
        masked_tokens = [self._mask_token(t) for t in tokens]
        new_cluster = LogCluster(
            cluster_id=self._next_cluster_id,
            log_template_tokens=masked_tokens,
            cluster_size=1,
            sample_message=clean_msg,
        )
        self.clusters[self._next_cluster_id] = new_cluster
        self._next_cluster_id += 1

        curr_node.clusters.append(new_cluster)
        params = self._extract_parameters(new_cluster.log_template_tokens, tokens)

        return DrainResult(
            cluster_id=new_cluster.cluster_id,
            template=new_cluster.template,
            parameters=params,
            cluster_size=1,
            is_new_cluster=True,
            similarity=1.0,
        )


# Global singleton parser instance
_global_drain: DrainParser | None = None


def get_default_drain_parser() -> DrainParser:
    global _global_drain
    if _global_drain is None:
        _global_drain = DrainParser(depth=4, similarity_threshold=0.5)
    return _global_drain
