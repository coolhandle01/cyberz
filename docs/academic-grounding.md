# Academic grounding

Some of cybersquad's structural decisions cite specific academic work at the
assertion site - a docstring, a comment, a model name. This file is the
longer-form "why these papers, what's actually in them, how do they map to
the pipeline" companion. The three papers below ground the
`AttackGraph` / `AttackTree` / `AttackForest` shape in `models/attack.py`
and `models/asset.py`.

## Schneier 1999 - attack trees

Bruce Schneier, *Attack Trees*, Dr. Dobb's Journal, December 1999.
<https://www.schneier.com/academic/archives/1999/12/attack_trees.html>

The original formalism. A goal at the root, AND/OR sub-goals as children,
leaves as atomic attack steps. Probabilities or costs hang off each leaf;
the tree as a whole answers "what is the cheapest / most likely path to
this goal?" by rolling values up.

Two important properties:

- **Forward-looking.** You start from a goal you want to achieve and
  decompose it. The tree is a *thinking tool*, typically hand-drawn,
  authored against intent.
- **Per-goal, not per-system.** One tree, one goal. A different objective
  is a different tree.

In cybersquad this maps to the **VR's worldview**. Per probe + target the
Vulnerability Researcher is asking "what would success look like and what
are the sub-conditions for it" - that decomposition is a Schneier tree.
The `AttackTree` shape in `models/attack.py` is intentionally degenerate
today (no `children`, no `decomposition: Literal["AND", "OR"]`) but the
naming reserves the room for a recursive shape later without renaming.

## Sheyner et al. 2002 - automated attack-graph generation and MDP analysis

Oleg Sheyner, Joshua Haines, Somesh Jha, Richard Lippmann, Jeannette M. Wing,
*Automated Generation and Analysis of Attack Graphs*, IEEE Symposium on
Security and Privacy 2002. DOI [10.1109/SECPRI.2002.1004377](https://doi.org/10.1109/SECPRI.2002.1004377).

Where Schneier draws trees by hand, Sheyner *generates a graph mechanically*.
Nodes are system states (which hosts have what privileges, which services
are reachable, what trust exists). Edges are atomic attacks - single
exploits that, when applied, transition the state. A path from an initial
state to a goal state is one attack scenario; the set of all such paths is
the attack graph.

**How they generated it.** Encode the network as state variables, the
exploits as a transition relation, the attacker goal as a property. Run a
symbolic model checker (they used NuSMV) and ask "find a counterexample
to 'goal is unreachable'." The standard model-checker returns one
counterexample; they extended it to return *all* paths, with cycles
handled. The output is the graph.

**Analyses on the graph.** Two are immediately useful:

- **Probabilistic / MDP.** Each edge has a probability of success, each
  goal has a value, so attack-graph reasoning frames cleanly as a Markov
  Decision Process. You can compute expected utility of a scenario and
  reason about *which path to try first* under uncertainty. The paper's
  own caveat is that the full MDP is intractable at scale (state
  explosion is the headline problem of model-checked attack graphs); in
  practice you approximate with A\* + a domain heuristic.
- **Minimum-cut.** What is the smallest set of edges you would need to
  remove to break every path to the goal? The defender's "minimum patch
  set" question. NP-hard but has decent approximation algorithms.

In cybersquad this maps to the **PT's worldview**. Given the trees the VR
produced, plan a search that maximises expected value of finding bugs -
Sheyner-style MDP reasoning, A\* + domain heuristic in practice. The
`AttackForest` docstring in `models/attack.py` cites Sheyner specifically
for this MDP framing.

## Ou et al. 2005 - MulVAL: a logic-based network security analyzer

Xinming Ou, Sudhakar Govindavajhala, Andrew W. Appel, *MulVAL: A Logic-based
Network Security Analyzer*, USENIX Security Symposium 2005.
<https://www.usenix.org/legacy/event/sec05/tech/full_papers/ou/ou.pdf>

The practical evolution. MulVAL stands for **MUL**ti-host, multi-stage
**V**ulnerability **A**nalysis. Where Sheyner's NuSMV approach blows up
combinatorially in state size (product of all host states),
MulVAL encodes the same problem in **Datalog**, evaluated by XSB Prolog.
Facts: vulnerability data (OVAL / NVD), network topology (firewall +
routing config), service configuration. Rules: "if X is vulnerable AND
attacker can reach X AND has privilege Y on Z, then attacker gains
privilege W on X." Run the reasoner, out pops a logical attack graph
where nodes are facts and edges are rule applications.

**Why it scales.** The graph represents fact-derivations, not state
transitions, so you sidestep the exploded state space. They report
results on networks with hundreds of hosts where the Sheyner-style
approach would be infeasible. Polynomial-time tabled evaluation in
Datalog is the underlying machinery.

**Why it is the right reference for cybersquad's vision.** MulVAL is wired
into *real scanner output*. Nessus / OpenVAS / similar reports get parsed
into Datalog facts. NVD CVSS scores feed exploitability and impact rules.
That maps directly onto the cybersquad shape: the OA produces facts about
the network, the VR's rules say "this attack achieves this privilege given
those preconditions," the PT reasons across all of it.

Open-source implementations live at variations of
<https://github.com/risksense/mulval> (forks are common; upstream activity
is intermittent). The academic descendants - probabilistic MulVAL,
defense-planning extensions, real-time variants - cover most of the
"automated attack-graph reasoning" sub-field.

## How they stack in cybersquad

| Role | Worldview | Reference |
|---|---|---|
| OSINT Analyst | Describes the graph. Collects facts about hosts, services, technologies, trust. | (graph-as-facts; MulVAL input shape) |
| Vulnerability Researcher | Finds the trees. Per probe + target, decomposes a sub-goal. | Schneier 1999 |
| Penetration Tester | Searches the forest. Expected-value path selection across trees. | Sheyner 2002 (MDP), A\* with a domain heuristic in practice |

Three formalisms from three traditions, each in the role its formalism is
good at. The naming in `models/attack.py` (`AttackGraph`, `AttackTree`,
`AttackForest`) is meant to make the role each agent plays legible to a
contributor who knows the literature.
