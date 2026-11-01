"""
simulator.py
------------
Core logic for the Enterprise Attack-Path Risk Simulator.

Defines the fictional network topology, risk-scoring formula,
and all helper functions used by the Streamlit UI.
"""

import networkx as nx

# ---------------------------------------------------------------------------
# 1. Network topology
# ---------------------------------------------------------------------------

# Each node has:
#   criticality  – how valuable the asset is to an attacker (1–10)
#   type         – display label used in the UI
NODE_ATTRIBUTES = {
    "Employee Workstation": {"criticality": 2, "type": "Endpoint"},
    "Web Server":           {"criticality": 4, "type": "Server"},
    "Application Server":   {"criticality": 6, "type": "Server"},
    "Database Server":      {"criticality": 9, "type": "Critical Asset"},
    "Domain Controller":    {"criticality": 10, "type": "Critical Asset"},
    "Backup Server":        {"criticality": 7, "type": "Critical Asset"},
}

# Edges: (source, target, connection_risk)
# connection_risk – how easy / likely this link is to exploit (1–10)
EDGES = [
    ("Employee Workstation", "Web Server",         3),
    ("Employee Workstation", "Application Server", 4),
    ("Web Server",           "Application Server", 5),
    ("Application Server",   "Database Server",    6),
    ("Application Server",   "Domain Controller",  7),
    ("Domain Controller",    "Backup Server",      5),
    ("Web Server",           "Database Server",    4),
]

# Nodes that represent high-value targets an attacker wants to reach
CRITICAL_ASSETS = {"Database Server", "Domain Controller", "Backup Server"}


def build_network() -> nx.DiGraph:
    """
    Build and return the fictional enterprise network as a directed graph.

    Returns
    -------
    nx.DiGraph
        Nodes carry 'criticality' and 'type' attributes.
        Edges carry a 'risk' weight.
    """
    G = nx.DiGraph()

    for name, attrs in NODE_ATTRIBUTES.items():
        G.add_node(name, **attrs)

    for src, dst, risk in EDGES:
        G.add_edge(src, dst, risk=risk)

    return G


# ---------------------------------------------------------------------------
# 2. Reachability
# ---------------------------------------------------------------------------

def get_reachable_critical_assets(G: nx.DiGraph, entry_point: str) -> list:
    """
    Return the list of critical assets reachable from *entry_point*.

    Uses simple BFS/DFS via nx.descendants, then filters by CRITICAL_ASSETS.
    """
    if entry_point not in G:
        return []

    reachable = nx.descendants(G, entry_point)
    return sorted(reachable & CRITICAL_ASSETS)


# ---------------------------------------------------------------------------
# 3. Risk scoring
# ---------------------------------------------------------------------------

def score_path(G: nx.DiGraph, path: list) -> float:
    """
    Calculate a risk score for a single path.

    Formula
    -------
    For each edge (u → v) in the path:
        edge_score = connection_risk(u, v) * criticality(v)

    total_score = sum(edge_scores) / path_length_penalty

    path_length_penalty = len(edges)  (longer paths are slightly discounted
                                       because each hop adds detection risk
                                       for the attacker)

    The result is rounded to two decimal places.
    """
    if len(path) < 2:
        return 0.0

    edges_in_path = list(zip(path[:-1], path[1:]))
    raw_score = sum(
        G[u][v]["risk"] * G.nodes[v]["criticality"]
        for u, v in edges_in_path
    )
    penalty = len(edges_in_path)
    return round(raw_score / penalty, 2)


def get_all_path_scores(G: nx.DiGraph, entry_point: str) -> list:
    """
    For every reachable critical asset, find all simple paths from
    *entry_point* and score each one.

    Returns
    -------
    list of dict
        Each dict has keys: 'path', 'target', 'score', 'risk_level'
        Sorted by score descending.
    """
    results = []
    targets = get_reachable_critical_assets(G, entry_point)

    for target in targets:
        for path in nx.all_simple_paths(G, entry_point, target):
            score = score_path(G, path)
            results.append({
                "path":       path,
                "target":     target,
                "score":      score,
                "risk_level": classify_risk(score),
            })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def classify_risk(score: float) -> str:
    """
    Map a numeric score to a human-readable risk level.

    Thresholds (tuned to the 1–10 criticality / risk scales above):
        score >= 40  → High Risk
        score >= 20  → Medium Risk
        otherwise    → Low Risk
    """
    if score >= 40:
        return "High Risk"
    if score >= 20:
        return "Medium Risk"
    return "Low Risk"


def get_highest_risk_path(path_scores: list) -> dict | None:
    """
    Return the single highest-scoring path dict, or None if the list
    is empty.
    """
    if not path_scores:
        return None
    return path_scores[0]   # already sorted descending


# ---------------------------------------------------------------------------
# 4. Defensive recommendations
# ---------------------------------------------------------------------------

RECOMMENDATIONS = {
    "High Risk": [
        "Immediately implement network segmentation to isolate critical assets.",
        "Enforce least-privilege access: restrict lateral movement between servers.",
        "Deploy an intrusion-detection system (IDS) on high-risk links.",
        "Require multi-factor authentication (MFA) on all privileged accounts.",
        "Audit and remove unnecessary firewall rules between these nodes.",
    ],
    "Medium Risk": [
        "Review and tighten firewall rules between the nodes on this path.",
        "Enforce least-privilege access for service accounts.",
        "Log and monitor all traffic traversing these connections.",
        "Consider micro-segmentation to limit blast radius.",
    ],
    "Low Risk": [
        "Continue regular patch management and vulnerability scanning.",
        "Periodically review access controls on these connections.",
        "Ensure security logging is enabled for these nodes.",
    ],
}


def get_recommendations(risk_level: str) -> list:
    """Return the defensive recommendations for a given risk level."""
    return RECOMMENDATIONS.get(risk_level, [])
