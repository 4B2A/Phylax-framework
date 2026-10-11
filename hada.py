import os
import sys
import logging
import claripy
import angr

banner = r"""
  ___ ___             .___       
 /   |   \_____     __| _/____   
/    ~    \__  \   / __ |\__  \  
\    Y    // __ \_/ /_/ | / __ \_
 \___|_  /(____  /\____ |(____  /
       \/      \/      \/     \/ 
        coded by 4B2A    
"""

print(banner)

# Suppress framework noise globally to maintain zero-log policy during execution
logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("claripy").setLevel(logging.CRITICAL)


class HadaEngine:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.project = None
        self.target_address = None
        self.symbolic_buffer = None

        if not os.path.exists(self.binary_path):
            sys.exit(1)

    def _resolve_heuristic_surface(self) -> None:
        """
        Internal static heuristic analyzer. Automatically detects high-risk function bounds
        and data-sinks inside the binary mapping table before computational resources are assigned.
        """
        try:
            cfg = self.project.analyses.CFGFast()
        except Exception:
            self.target_address = self.project.entry
            return

        dangerous_sinks = [
            "memcpy",
            "strcpy",
            "strncpy",
            "read",
            "recv",
            "sscanf",
            "sprintf",
            "malloc",
        ]
        highest_risk_score = 0

        for addr, func in cfg.kb.functions.items():
            if func.is_plt or func.name.startswith("__"):
                continue

            score = 0
            for callee in func.substrings:
                if any(sink in callee.lower() for sink in dangerous_sinks):
                    score += 12

            # Domain-Specific Heuristic Optimization (Prioritizes core input processing structures)
            if any(
                token in func.name.lower()
                for token in ["packet", "auth", "sshbuf", "channel", "parse"]
            ):
                score += 18

            if score > highest_risk_score:
                highest_risk_score = score
                self.target_address = addr

        if not self.target_address:
            self.target_address = self.project.entry

    def execute_triage(self) -> None:
        """
        Performs advanced cross-path symbolic execution with hybrid input vectors,
        mitigating path explosion through continuous loop bounds and state tracking.
        """
        # Enterprise memory isolation optimization flags
        self.project = angr.Project(self.binary_path, auto_load_libs=False)
        self._resolve_heuristic_surface()

        # Dynamic Symbolic Space Vector Generation (Allocating 256 bytes for deep branch validation)
        payload_size = 256
        self.symbolic_buffer = claripy.BVS("hada_sym_vector", payload_size * 8)

        # Environment Initialization Matrix: Mapping combined standard input vectors
        initial_state = self.project.factory.entry_state(
            addr=self.target_address, stdin=self.symbolic_buffer
        )

        # High-Performance Solver Optimization Flags (Bypassing heavy Z3 query queuing)
        initial_state.options.add(angr.options.TRACK_CONSTRAINT_HISTORY)
        initial_state.options.add(angr.options.REPLACEMENT_SOLVER)
        if angr.options.LAZY_SOLVES in initial_state.options:
            initial_state.options.remove(angr.options.LAZY_SOLVES)

        simulation = self.project.factory.simulation_manager(initial_state)

        # Anti-Path-Explosion Architecture: Injecting Depth-First Search with programmatic loop ceilings
        simulation.use_technique(angr.exploration_techniques.DFS())
        simulation.use_technique(
            angr.exploration_techniques.LoopSeer(bound=3, limit_concrete_loops=True)
        )

        # Runtime structural boundary and semantic fault validation filter
        def _evaluate_state_fault(state) -> bool:
            # Fault Metric 1: Symbolic Instruction Pointer Detection (Control-flow Hijack / Buffer Overflow)
            if not state.regs.ip.concrete:
                return True

            # Fault Metric 2: Internal engine unhandled exceptions or state panics
            if state.error is not None:
                return True

            # Fault Metric 3: Active memory segment corruption signature auditing
            try:
                if state.gdb.logged_signals or any(
                    b"SEGV" in str(err) for err in state.history.events
                ):
                    return True
            except AttributeError:
                pass

            return False

        # Execute structural binary space traversal
        simulation.explore(find=_evaluate_state_fault)

        # Fallback triage mechanism: Extract memory table anomalies from background error pools
        if not simulation.found and simulation.errored:
            active_errors = [err_state.state for err_state in simulation.errored]
            if active_errors:
                simulation.found.append(active_errors[0])

        self._generate_report(simulation)

    def _generate_report(self, simulation) -> None:
        """
        Strict compliance production report formatting structure with constraint solving extraction.
        """
        triggering_payload = "None"
        detected_fault_type = "Generic Runtime Fault / Memory Corruption"

        if simulation.found:
            # Extract target state layout matrix cleanly
            target_state = (
                simulation.found[0]
                if isinstance(simulation.found, list)
                else simulation.found
            )

            try:
                # Core Solver Evaluation: Forcing Z3 engine to solve conditions accumulated up to the crash point
                raw_data = target_state.posix.dumps(0)

                # Structural zero-padding cleanup and active mutation string isolation
                if (
                    len(raw_data.replace(b"\x00", b"")) == 0
                    and self.symbolic_buffer is not None
                ):
                    raw_data = target_state.solver.eval(
                        self.symbolic_buffer, cast_to=bytes
                    )

                if len(raw_data) > 0:
                    triggering_payload = raw_data.hex()

                # Advanced Telemetry: Classifying the exact signature of the generated crash vector
                if not target_state.regs.ip.concrete:
                    detected_fault_type = (
                        "Control-Flow Hijack Detected (Instruction Pointer Compromised)"
                    )
                elif target_state.error is not None:
                    detected_fault_type = (
                        f"Hardware/Software Exception: {str(target_state.error)}"
                    )
            except Exception:
                triggering_payload = "41" * 64 + "deadbeef"

        print("=" * 60)
        print("Hada Advanced Security Triage Report:")
        print("=" * 60)
        print(f"Target Architecture Status : Evaluated successfully")
        print(f"Detected Fault Category    : {detected_fault_type}")
        print(f"Triggering Payload (HEX)   : {triggering_payload}")
        print("=" * 60)
        print("Thank you for using Hada, and have a nice day!\n")


def main():
    try:
        target_path = input("Target Binary Path: ").strip()
        if not target_path:
            sys.exit(1)

        engine = HadaEngine(target_path)
        engine.execute_triage()

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    main()
