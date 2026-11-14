"""
Mule Account Detection Module for UPI Fraud Guard.

Uses NetworkX graph-based financial transaction network analysis to identify:
- High Fan-In Nodes (Multiple unique senders transferring to one recipient)
- Rapid Fan-Out Nodes (Single account distributing funds to many secondary accounts)
- Circular Money Trails (A -> B -> C -> A)
- Degree Centrality and High-Connectivity Suspicious Nodes
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Set
import networkx as nx

logger = logging.getLogger("upi_fraud_guard.mule_detection")


class MuleAccountDetector:
    """Graph-based transaction network analyzer for financial mule accounts."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self._seed_demo_graph()

    def _seed_demo_graph(self) -> None:
        """Seeds initial synthetic transaction graph edges for demonstration & testing."""
        demo_edges = [
            ("user_a@upi", "mule_target@ybl", {"amount": 15000, "timestamp": "2026-03-01T10:00:00"}),
            ("user_b@upi", "mule_target@ybl", {"amount": 20000, "timestamp": "2026-03-01T10:05:00"}),
            ("user_c@upi", "mule_target@ybl", {"amount": 18000, "timestamp": "2026-03-01T10:12:00"}),
            ("user_d@upi", "mule_target@ybl", {"amount": 25000, "timestamp": "2026-03-01T10:18:00"}),
            ("user_e@upi", "mule_target@ybl", {"amount": 12000, "timestamp": "2026-03-01T10:25:00"}),
            ("mule_target@ybl", "crypto_cashout@okaxis", {"amount": 85000, "timestamp": "2026-03-01T10:30:00"}),
            # Circular trail
            ("acc_x@upi", "acc_y@paytm", {"amount": 50000, "timestamp": "2026-03-01T11:00:00"}),
            ("acc_y@paytm", "acc_z@sbi", {"amount": 49000, "timestamp": "2026-03-01T11:15:00"}),
            ("acc_z@sbi", "acc_x@upi", {"amount": 48500, "timestamp": "2026-03-01T11:30:00"}),
        ]
        for sender, receiver, attr in demo_edges:
            self.graph.add_edge(sender, receiver, **attr)

    def add_transaction(self, sender: str, receiver: str, amount: float) -> None:
        if sender and receiver:
            self.graph.add_edge(
                sender.strip().lower(),
                receiver.strip().lower(),
                amount=amount,
            )

    def analyze_account(self, account_vpa: str) -> Dict[str, Any]:
        """Analyzes a specific account VPA for mule risk indicators."""
        vpa = account_vpa.strip().lower()
        if not self.graph.has_node(vpa):
            return {
                "vpa": account_vpa,
                "is_mule_candidate": False,
                "mule_risk_score": 0.0,
                "in_degree": 0,
                "out_degree": 0,
                "reasons": ["No transaction network graph edges recorded for this account"],
            }

        in_degree = self.graph.in_degree(vpa)
        out_degree = self.graph.out_degree(vpa)
        reasons: List[str] = []
        mule_score = 0.0

        # High Fan-In Check (Multiple senders -> Single account)
        if in_degree >= 4:
            reasons.append(f"High Fan-In: {in_degree} distinct senders transferring funds into this account")
            mule_score += 0.55
        elif in_degree >= 2:
            reasons.append(f"Multiple senders ({in_degree}) transferring to this account")
            mule_score += 0.25

        # Fan-Out Check
        if out_degree >= 3:
            reasons.append(f"Rapid Fan-Out: Distributing funds to {out_degree} distinct downstream accounts")
            mule_score += 0.35

        # Circular Cycle Detection
        try:
            cycles = [c for c in nx.simple_cycles(self.graph) if vpa in c]
            if cycles:
                reasons.append(f"Circular Transaction Trail Detected: Loop involving {len(cycles[0])} accounts")
                mule_score += 0.60
        except Exception:
            pass

        # Centrality
        centrality = nx.degree_centrality(self.graph).get(vpa, 0.0)

        is_candidate = mule_score >= 0.40
        return {
            "vpa": account_vpa,
            "is_mule_candidate": is_candidate,
            "mule_risk_score": round(min(mule_score, 0.99), 3),
            "in_degree": in_degree,
            "out_degree": out_degree,
            "degree_centrality": round(centrality, 3),
            "reasons": reasons if reasons else ["Normal graph connectivity pattern"],
        }

    def get_network_summary(self) -> Dict[str, Any]:
        """Returns overall graph statistics and top identified mule candidates."""
        suspicious_nodes: List[Dict[str, Any]] = []
        for node in self.graph.nodes():
            analysis = self.analyze_account(node)
            if analysis["is_mule_candidate"]:
                suspicious_nodes.append(analysis)

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "suspicious_mule_count": len(suspicious_nodes),
            "mule_candidates": suspicious_nodes,
        }


# Singleton instance
mule_detector = MuleAccountDetector()
