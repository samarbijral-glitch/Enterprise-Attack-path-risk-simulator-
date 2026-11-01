"""
test_simulator.py
-----------------
Unit tests for the Enterprise Attack-Path Risk Simulator.

Run with:
    python -m unittest test_simulator.py
"""

import unittest

from simulator import (
    build_network,
    get_reachable_critical_assets,
    score_path,
    get_all_path_scores,
    get_highest_risk_path,
    classify_risk,
    CRITICAL_ASSETS,
)


class TestBuildNetwork(unittest.TestCase):
    """Tests for build_network()."""

    def setUp(self):
        self.G = build_network()

    def test_all_nodes_present(self):
        """All six fictional nodes must exist in the graph."""
        expected = {
            "Employee Workstation",
            "Web Server",
            "Application Server",
            "Database Server",
            "Domain Controller",
            "Backup Server",
        }
        self.assertEqual(set(self.G.nodes()), expected)

    def test_node_has_criticality(self):
        """Every node must carry a 'criticality' attribute."""
        for node in self.G.nodes():
            self.assertIn(
                "criticality",
                self.G.nodes[node],
                msg=f"Node '{node}' is missing 'criticality'",
            )

    def test_node_has_type(self):
        """Every node must carry a 'type' attribute."""
        for node in self.G.nodes():
            self.assertIn(
                "type",
                self.G.nodes[node],
                msg=f"Node '{node}' is missing 'type'",
            )

    def test_edges_have_risk(self):
        """Every edge must carry a 'risk' attribute."""
        for u, v in self.G.edges():
            self.assertIn(
                "risk",
                self.G[u][v],
                msg=f"Edge ({u} → {v}) is missing 'risk'",
            )

    def test_graph_is_directed(self):
        """The graph must be directed (DiGraph)."""
        import networkx as nx
        self.assertIsInstance(self.G, nx.DiGraph)

    def test_criticality_domain_controller(self):
        """Domain Controller should have the highest criticality (10)."""
        self.assertEqual(self.G.nodes["Domain Controller"]["criticality"], 10)


class TestReachableCriticalAssets(unittest.TestCase):
    """Tests for get_reachable_critical_assets()."""

    def setUp(self):
        self.G = build_network()

    def test_workstation_reaches_all_critical(self):
        """Employee Workstation should be able to reach all three critical assets."""
        reachable = get_reachable_critical_assets(self.G, "Employee Workstation")
        self.assertEqual(set(reachable), CRITICAL_ASSETS)

    def test_domain_controller_reaches_backup(self):
        """Domain Controller should reach Backup Server (direct edge)."""
        reachable = get_reachable_critical_assets(self.G, "Domain Controller")
        self.assertIn("Backup Server", reachable)

    def test_database_server_reaches_nothing(self):
        """Database Server has no outgoing edges to other critical assets."""
        reachable = get_reachable_critical_assets(self.G, "Database Server")
        # Database Server is a sink — no outgoing edges in the topology
        self.assertEqual(reachable, [])

    def test_invalid_entry_point_returns_empty(self):
        """An entry point not in the graph should return an empty list."""
        reachable = get_reachable_critical_assets(self.G, "Nonexistent Node")
        self.assertEqual(reachable, [])


class TestRiskScoreCalculation(unittest.TestCase):
    """Tests for score_path() and classify_risk()."""

    def setUp(self):
        self.G = build_network()

    def test_single_hop_score(self):
        """
        Employee Workstation → Web Server:
            edge risk = 3, Web Server criticality = 4
            score = (3 * 4) / 1 = 12.0
        """
        path = ["Employee Workstation", "Web Server"]
        self.assertEqual(score_path(self.G, path), 12.0)

    def test_two_hop_score(self):
        """
        Employee Workstation → Application Server → Database Server:
            hop1: risk=4, crit=6  → 24
            hop2: risk=6, crit=9  → 54
            total = 78, edges = 2  → score = 39.0
        """
        path = ["Employee Workstation", "Application Server", "Database Server"]
        self.assertEqual(score_path(self.G, path), 39.0)

    def test_trivial_path_score_is_zero(self):
        """A path with only one node (no edges) should score 0."""
        self.assertEqual(score_path(self.G, ["Employee Workstation"]), 0.0)

    def test_classify_high_risk(self):
        self.assertEqual(classify_risk(42.0), "High Risk")

    def test_classify_medium_risk(self):
        self.assertEqual(classify_risk(25.0), "Medium Risk")

    def test_classify_low_risk(self):
        self.assertEqual(classify_risk(10.0), "Low Risk")

    def test_classify_boundary_high(self):
        """Score exactly at 40 is High Risk."""
        self.assertEqual(classify_risk(40.0), "High Risk")

    def test_classify_boundary_medium(self):
        """Score exactly at 20 is Medium Risk."""
        self.assertEqual(classify_risk(20.0), "Medium Risk")

    def test_score_is_float(self):
        """score_path must always return a float."""
        path = ["Employee Workstation", "Web Server"]
        result = score_path(self.G, path)
        self.assertIsInstance(result, float)


class TestHighestRiskPath(unittest.TestCase):
    """Tests for get_all_path_scores() and get_highest_risk_path()."""

    def setUp(self):
        self.G = build_network()

    def test_paths_returned_for_workstation(self):
        """There should be at least one path from Employee Workstation."""
        scores = get_all_path_scores(self.G, "Employee Workstation")
        self.assertGreater(len(scores), 0)

    def test_paths_sorted_descending(self):
        """Paths must be sorted from highest score to lowest."""
        scores = get_all_path_scores(self.G, "Employee Workstation")
        score_values = [s["score"] for s in scores]
        self.assertEqual(score_values, sorted(score_values, reverse=True))

    def test_highest_risk_path_is_first(self):
        """get_highest_risk_path returns the top-scored entry."""
        scores = get_all_path_scores(self.G, "Employee Workstation")
        top = get_highest_risk_path(scores)
        self.assertEqual(top["score"], scores[0]["score"])

    def test_highest_risk_path_empty_returns_none(self):
        """get_highest_risk_path returns None when given an empty list."""
        self.assertIsNone(get_highest_risk_path([]))

    def test_each_result_has_required_keys(self):
        """Every result dict must contain path, target, score, risk_level."""
        scores = get_all_path_scores(self.G, "Employee Workstation")
        for item in scores:
            for key in ("path", "target", "score", "risk_level"):
                self.assertIn(key, item, msg=f"Key '{key}' missing from result")

    def test_target_is_critical_asset(self):
        """Every path's target must be a known critical asset."""
        scores = get_all_path_scores(self.G, "Employee Workstation")
        for item in scores:
            self.assertIn(item["target"], CRITICAL_ASSETS)

    def test_no_paths_from_sink_node(self):
        """Database Server is a sink — no paths should be returned."""
        scores = get_all_path_scores(self.G, "Database Server")
        self.assertEqual(scores, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
