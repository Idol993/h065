from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from dependency_auditor.parsers.python_parser import Dependency


@dataclass
class CircularDependency:
    cycle: list[str]
    length: int


class CircularDetector:

    def build_graph(self, deps: list[Dependency]) -> nx.DiGraph:
        graph = nx.DiGraph()
        for dep in deps:
            graph.add_node(dep.name)
            for sub in dep.dependencies:
                graph.add_edge(dep.name, sub)
        return graph

    def detect(self, deps: list[Dependency]) -> list[CircularDependency]:
        graph = self.build_graph(deps)
        raw_cycles: list[list[str]] = []
        try:
            raw_cycles = list(nx.simple_cycles(graph))
        except nx.NetworkXError:
            pass

        seen: set[frozenset[str]] = set()
        results: list[CircularDependency] = []

        for cycle in raw_cycles:
            if len(cycle) < 2:
                continue
            closed = cycle + [cycle[0]]
            key = frozenset(cycle)
            if key in seen:
                continue
            seen.add(key)
            results.append(CircularDependency(
                cycle=closed,
                length=len(cycle),
            ))

        results.sort(key=lambda c: c.length)
        return results

    def get_dependency_tree(
        self,
        deps: list[Dependency],
        max_depth: int = 5,
    ) -> dict:
        dep_map: dict[str, Dependency] = {d.name: d for d in deps}
        cycles = self.detect(deps)
        cycle_edges: set[tuple[str, str]] = set()
        for cd in cycles:
            for i in range(len(cd.cycle) - 1):
                cycle_edges.add((cd.cycle[i], cd.cycle[i + 1]))

        def _build(name: str, depth: int, visited: set[str]) -> dict:
            if depth > max_depth:
                return {}
            if name in visited:
                return {"↩ " + name: {}}
            visited = visited | {name}
            dep = dep_map.get(name)
            if dep is None or not dep.dependencies:
                return {}
            tree: dict[str, dict] = {}
            for sub in dep.dependencies:
                is_circular = (name, sub) in cycle_edges
                label = "⟳ " + sub if is_circular else sub
                subtree = _build(sub, depth + 1, visited)
                tree[label] = subtree
            return tree

        root: dict[str, dict] = {}
        for dep in deps:
            root[dep.name] = _build(dep.name, 1, set())
        return root
