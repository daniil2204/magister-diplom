"""SC10: controlled delegatecall.

phi_DC (2.10) is dcall_i(a) AND Ctrl(a). The target is the operation itself.

Every delegatecall becomes a target, including those whose destination comes from storage: the
static stage over-approximates, Ctrl is decided precisely by the symbolic stage, and A(t) already
separates the two cases (an argument destination gives A = 1, a storage destination A = 0.5).
"""

from __future__ import annotations

from hsa.config import VulnClass
from hsa.model import Target
from hsa.static.base import Analysis, build_target, is_delegatecall


class DelegatecallDetector:
    """One target per delegatecall operation."""

    vuln_class = VulnClass.DC

    def detect(self, analysis: Analysis) -> list[Target]:
        targets: list[Target] = []
        for expansion in analysis.expansions.values():
            for vertex in sorted(expansion.vertices(), key=lambda v: (v.node_key, len(v.stack))):
                node = expansion.node(vertex)
                for index, ir in enumerate(node.irs):
                    if not is_delegatecall(ir):
                        continue
                    targets.append(
                        build_target(
                            analysis,
                            expansion,
                            vertex,
                            VulnClass.DC,
                            # E_t = {delegatecall address, calldata}
                            key_expressions=[ir.destination, *ir.arguments],
                            op_index=index,
                        )
                    )
        return targets
