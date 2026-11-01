# Enterprise Attack-Path Risk Simulator

## 🛡️ What is this?

An **educational cybersecurity simulation** built for an ICT Skills Workshop.  
It models a fictional enterprise network and shows how a hypothetical attacker could move between connected systems to reach critical assets.

> **Safety notice:** This project performs no real network scanning, exploitation, or external connections. All data is fictional and local.

---

## 📁 Project Structure

```
Enterprise-Attack-Path-Simulator/
├── app.py             # Streamlit UI
├── simulator.py       # Core logic (graph, risk scoring, path finding)
├── test_simulator.py  # Unit tests
├── requirements.txt   # Python dependencies
├── README.md          # This file
└── .gitignore
```

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 2. Run the application

```bash
python -m streamlit run app.py
```

Open the URL shown in your terminal (usually `http://localhost:8501`).

### 3. Run the unit tests

```bash
python -m unittest test_simulator.py
```

---

## 🗺️ Fictional Network Topology

```
Employee Workstation ──► Web Server ──► Application Server ──► Database Server
         │                                      │
         └──────────────────────────────────────┤
                                                ▼
                                       Domain Controller ──► Backup Server
```

| Node                 | Type           | Criticality |
|----------------------|----------------|-------------|
| Employee Workstation | Endpoint       | 2           |
| Web Server           | Server         | 4           |
| Application Server   | Server         | 6           |
| Database Server      | Critical Asset | 9           |
| Domain Controller    | Critical Asset | 10          |
| Backup Server        | Critical Asset | 7           |

---

## 📐 Risk-Scoring Formula

For every edge **u → v** in a path:

```
edge_score = connection_risk(u → v) × criticality(v)
```

Aggregated across the path:

```
path_score = Σ edge_scores  ÷  number_of_edges
```

Dividing by path length gives a slight discount to longer paths — each extra hop increases the attacker's chance of detection.

| Score | Risk Level    |
|-------|---------------|
| ≥ 40  | 🔴 High Risk  |
| ≥ 20  | 🟡 Medium Risk|
| < 20  | 🟢 Low Risk   |

---

## 🧪 Tests

Tests cover:

- Graph construction (nodes, edges, attributes)
- Reachable critical asset detection
- Risk score calculation (single-hop, multi-hop, boundary conditions)
- Highest-risk path identification

```bash
python -m unittest test_simulator.py -v
```

---

## 🛠️ Technologies

| Library    | Purpose                          |
|------------|----------------------------------|
| Streamlit  | Interactive web UI               |
| NetworkX   | Directed graph & path algorithms |
| Plotly     | Network graph visualisation      |

---

## 📚 Learning Objectives

After exploring this simulator you should be able to:

1. Explain what lateral movement means in an enterprise network.
2. Describe why critical assets need stronger isolation.
3. Identify at least three defensive controls that reduce attack-path risk.
4. Read a simple directed graph and trace a hypothetical attack path.

---

## ⚠️ Disclaimer

This project is **strictly educational**. The network topology, node names, and risk values are entirely fictional. No real systems are modelled, scanned, or accessed.
