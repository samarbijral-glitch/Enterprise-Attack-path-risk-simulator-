"""
app.py
------
Streamlit front-end for the Enterprise Attack-Path Risk Simulator.

Run with:
    python -m streamlit run app.py
"""

import streamlit as st
import plotly.graph_objects as go
import networkx as nx

from simulator import (
    build_network,
    get_reachable_critical_assets,
    get_all_path_scores,
    get_highest_risk_path,
    get_recommendations,
    CRITICAL_ASSETS,
    NODE_ATTRIBUTES,
)

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Enterprise Attack-Path Risk Simulator",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RISK_COLOURS = {
    "High Risk":   "#e74c3c",
    "Medium Risk": "#f39c12",
    "Low Risk":    "#27ae60",
}

NODE_COLOUR_MAP = {
    "Endpoint":       "#5dade2",   # blue
    "Server":         "#f0b27a",   # orange
    "Critical Asset": "#ec7063",   # red
}


def build_plotly_figure(G: nx.DiGraph, highlight_path: list | None = None) -> go.Figure:
    """
    Build a Plotly figure for the network graph.
    Optionally highlights *highlight_path* edges in red.
    """
    # Use a spring layout for consistent, readable placement
    pos = nx.spring_layout(G, seed=42, k=2.5)

    # ---- edges ----
    edge_traces = []
    highlight_set = set()
    if highlight_path and len(highlight_path) >= 2:
        highlight_set = set(zip(highlight_path[:-1], highlight_path[1:]))

    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        is_highlighted = (u, v) in highlight_set
        colour = "#e74c3c" if is_highlighted else "#aab7b8"
        width  = 4         if is_highlighted else 1.5

        edge_traces.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode="lines",
                line=dict(width=width, color=colour),
                hoverinfo="none",
                showlegend=False,
            )
        )

    # ---- nodes ----
    node_x, node_y, node_text, node_colours, node_sizes = [], [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        attrs   = G.nodes[node]
        colour  = NODE_COLOUR_MAP.get(attrs["type"], "#aab7b8")
        size    = 28 if node in CRITICAL_ASSETS else 20
        if highlight_path and node in highlight_path:
            colour = "#e74c3c"
            size   = 32
        node_colours.append(colour)
        node_sizes.append(size)
        node_text.append(
            f"<b>{node}</b><br>"
            f"Type: {attrs['type']}<br>"
            f"Criticality: {attrs['criticality']}/10"
        )

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=list(G.nodes()),
        textposition="top center",
        hovertext=node_text,
        hoverinfo="text",
        marker=dict(
            size=node_sizes,
            color=node_colours,
            line=dict(width=2, color="#2c3e50"),
        ),
        showlegend=False,
    )

    fig = go.Figure(data=edge_traces + [node_trace])
    fig.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="#0e1117",
        plot_bgcolor="#0e1117",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=480,
    )
    return fig


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
st.title("🛡️ Enterprise Attack-Path Risk Simulator")
st.caption(
    "An educational tool that models how a hypothetical attacker "
    "could move through a fictional enterprise network to reach critical assets. "
    "**No real networks are scanned or accessed.**"
)

G = build_network()

# ---- Sidebar ----
with st.sidebar:
    st.header("⚙️ Simulation Controls")

    all_nodes = sorted(G.nodes())
    default_idx = all_nodes.index("Employee Workstation")
    entry_point = st.selectbox(
        "Select simulated entry point:",
        all_nodes,
        index=default_idx,
        help="The node where the hypothetical attacker gains an initial foothold.",
    )

    run_sim = st.button("▶ Run Simulation", use_container_width=True, type="primary")

    st.divider()
    st.subheader("📐 Risk-Scoring Formula")
    st.markdown(
        """
For each edge **u → v** on a path:

```
edge_score = connection_risk(u→v) × criticality(v)
```

Then across the whole path:

```
path_score = Σ edge_scores  ÷  number_of_edges
```

**Why divide by path length?**  
Longer paths are slightly discounted — each additional hop increases
detection risk for the attacker and reduces overall probability.

**Risk thresholds:**
| Score | Level |
|-------|-------|
| ≥ 40  | 🔴 High Risk |
| ≥ 20  | 🟡 Medium Risk |
| < 20  | 🟢 Low Risk |
        """
    )

    st.divider()
    st.subheader("🗺️ Legend")
    st.markdown(
        """
- 🔵 **Blue node** — Endpoint  
- 🟠 **Orange node** — Server  
- 🔴 **Red node** — Critical Asset  
- 🔴 **Red edge** — Highest-risk attack path  
        """
    )

# ---- Main area ----
col_graph, col_results = st.columns([3, 2], gap="large")

with col_graph:
    st.subheader("Network Topology")

    if run_sim:
        path_scores = get_all_path_scores(G, entry_point)
        top = get_highest_risk_path(path_scores)
        highlight = top["path"] if top else None
        st.session_state["path_scores"] = path_scores
        st.session_state["entry_point"] = entry_point
    else:
        highlight = None

    fig = build_plotly_figure(G, highlight_path=highlight)
    st.plotly_chart(fig, use_container_width=True)

with col_results:
    st.subheader("Simulation Results")

    if not run_sim and "path_scores" not in st.session_state:
        st.info("Select an entry point and click **▶ Run Simulation** to begin.")

    elif run_sim or "path_scores" in st.session_state:
        # Use the freshly computed scores (or the cached ones)
        if run_sim:
            path_scores = st.session_state["path_scores"]
            ep          = st.session_state["entry_point"]
        else:
            path_scores = st.session_state["path_scores"]
            ep          = st.session_state.get("entry_point", entry_point)

        reachable = get_reachable_critical_assets(G, ep)

        if not reachable:
            st.warning(
                f"No critical assets are reachable from **{ep}** "
                "with the current topology."
            )
        else:
            st.markdown(f"**Entry point:** `{ep}`")

            # Reachable critical assets
            st.markdown("#### 🎯 Reachable Critical Assets")
            for asset in reachable:
                st.markdown(f"- {asset}")

            # Highest-risk path callout
            top = get_highest_risk_path(path_scores)
            if top:
                risk_colour = RISK_COLOURS[top["risk_level"]]
                st.markdown("#### ⚠️ Highest-Risk Path")
                path_str = " → ".join(top["path"])
                st.markdown(
                    f"""
<div style="
    background:{risk_colour}22;
    border-left:4px solid {risk_colour};
    padding:10px 14px;
    border-radius:4px;
    font-size:0.93em;
">
<b>{path_str}</b><br>
Score: <b>{top['score']}</b> &nbsp;|&nbsp; 
<span style="color:{risk_colour};font-weight:bold">{top['risk_level']}</span>
</div>
""",
                    unsafe_allow_html=True,
                )

            # All paths table
            st.markdown("#### 📋 All Attack Paths")
            for item in path_scores:
                colour = RISK_COLOURS[item["risk_level"]]
                badge  = (
                    f'<span style="background:{colour};color:#fff;'
                    f'padding:1px 8px;border-radius:10px;font-size:0.8em;">'
                    f'{item["risk_level"]}</span>'
                )
                with st.expander(
                    f"{' → '.join(item['path'])}  |  Score: {item['score']}"
                ):
                    st.markdown(badge, unsafe_allow_html=True)
                    st.markdown(f"**Path length:** {len(item['path']) - 1} hop(s)")

                    recs = get_recommendations(item["risk_level"])
                    st.markdown("**Defensive Recommendations:**")
                    for rec in recs:
                        st.markdown(f"- {rec}")
