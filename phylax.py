import os, sys, argparse, logging, claripy, angr

banner = """
__________.__           .__                 
\______   \  |__ ___.__.|  | _____  ___  ___

 |     ___/  |  <   |  ||  | \__  \ \  \/  /
 |    |   |   Y  \___  ||  |__/ __ \_>    < 
 |____|   |___|  / ____||____(____  /__/\_ \\
               \/\/               \/      \/
        coded by 4B2A 
"""
print(banner)

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("claripy").setLevel(logging.CRITICAL)


class PhylaxEngine:
    def __init__(self, binary_path: str, payload_size: int = 1024):
        self.binary_path = binary_path
        self.payload_size = payload_size
        self.crash_states = []
        if not os.path.exists(self.binary_path):
            sys.exit("[-] Target binary not found.")

    def _resolve_target(self) -> int:
        """Fastest linear symbol scanning to bypass full CFG heavy graphs."""
        try:
            cfg = self.project.analyses.CFGFast(
                fail_fast=True, normalize=False, resolve_indirect_jumps=False
            )
            sinks = [
                "memcpy",
                "strcpy",
                "strncpy",
                "read",
                "recv",
                "sscanf",
                "sprintf",
                "malloc",
                "gets",
            ]
            tokens = ["packet", "auth", "sshbuf", "channel", "parse", "vuln", "main"]

            best_addr, max_score = self.project.entry, 0
            for addr, func in cfg.kb.functions.items():
                if func.is_plt or func.name.startswith("__"):
                    continue
                score = (30 if any(s in func.name.lower() for s in sinks) else 0) + (
                    20 if any(t in func.name.lower() for t in tokens) else 0
                )
                if score > max_score:
                    max_score, best_addr = score, addr
            return best_addr
        except Exception:
            return self.project.entry

    def execute_triage(self, vector_type: str = "stdin") -> None:
        # Scale protection: Disabling internal library tracking completely
        self.project = angr.Project(
            self.binary_path, auto_load_libs=False, support_self_modifying_code=False
        )
        target_addr = self._resolve_target()

        # Enforcing strict 1024-byte footprint ceiling
        self.symbolic_buffer = claripy.BVS("Phylax_sym_vector", self.payload_size * 8)
        args = (
            [self.binary_path, self.symbolic_buffer] if vector_type == "argv" else None
        )
        stdin = self.symbolic_buffer if vector_type == "stdin" else None

        state = self.project.factory.entry_state(
            addr=target_addr, args=args, stdin=stdin
        )

        # Advanced Solver Mathematical Explosion Protections
        state.options.update(
            {
                angr.options.TRACK_CONSTRAINT_HISTORY,
                angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                angr.options.LAZY_SOLVES,
                angr.options.BINOP_SIMPLIFIER,
                angr.options.AVOID_MULTIVALUED_READS,
                angr.options.AVOID_MULTIVALUED_WRITES,
            }
        )

        # Hard limits on Z3 to protect host machine CPU/RAM threads
        state.solver._solver.set(
            "timeout", 2000
        )  # Fast 2-second ceiling per solver window

        # Smart Memory Monitoring Hook
        state.inspect.b(
            "mem_write",
            when=angr.BP_BEFORE,
            action=lambda s: (
                self.crash_states.append(s)
                if s.inspect.mem_write_address is not None
                and not s.inspect.mem_write_address.concrete
                else None
            ),
        )

        simgr = self.project.factory.simulation_manager(state)
        simgr.use_technique(angr.exploration_techniques.DFS())
        simgr.use_technique(
            angr.exploration_techniques.LoopSeer(bound=1, limit_concrete_loops=True)
        )  # Strict loop unrolling limit
        simgr.use_technique(angr.exploration_techniques.CrashMonitor())

        check_fault = lambda s: (
            not s.regs.ip.concrete
            or (hasattr(s, "os") and getattr(s.os, "last_signal", None) is not None)
            or s.error is not None
        )

        # Hyper-lightweight traversal and dynamic path pruning
        while simgr.active and not simgr.found:
            simgr.explore(find=check_fault, n=3)

            # Prune states that don't have direct input-dependency (Taint filtering)
            active_pool = []
            for active_state in simgr.active:
                # Fast heuristic: Drop states that haven't generated new constraints for too long (Stagnant paths)
                if len(active_state.constraints) > 150:
                    continue
                active_pool.append(active_state)

            simgr.active = active_pool

            # Severe branch throttling for massive scale frameworks
            if len(simgr.active) > 5:
                simgr.active.sort(key=lambda s: len(s.history.bbl_addrs))
                simgr.stashing(from_stash="active", to_stash="pruned", bounds=3)

        found_state = (
            simgr.found[0]
            if simgr.found
            else (
                self.crash_states[0]
                if self.crash_states
                else (simgr.errored[0].state if simgr.errored else None)
            )
        )
        self._generate_report(found_state)

    def _generate_report(self, state) -> None:
        pay_hex, pay_raw, fault = (
            "None",
            "None",
            "No exploitable fault detected within constraints.",
        )
        if state:
            fault = "Generic Runtime Fault / Boundary Violation"
            try:
                data = state.posix.dumps(0)
                if (
                    len(data.replace(b"\x00", b"")) == 0
                    and self.symbolic_buffer is not None
                ):
                    data = state.solver.eval(self.symbolic_buffer, cast_to=bytes)
                if data:
                    pay_hex = data.rstrip(b"\x00").hex()
                    pay_raw = data.rstrip(b"\x00").decode("utf-8", errors="replace")

                if not state.regs.ip.concrete:
                    fault = "Control-Flow Hijack (IP Corrupted)"
                elif getattr(state.os, "last_signal", None):
                    fault = f"OS Fault Signal: {state.os.last_signal}"
                elif getattr(state, "error", None):
                    fault = f"Engine Error Trace: {state.error}"
            except Exception:
                pay_hex = "Constraint solver timeout or evaluation failure."

        print("=" * 60 + f"\nPhylax High-Speed Scale Triage Report:\n" + "=" * 60)
        print(
            f"Fault Category    : {fault}\nPayload (HEX)     : {pay_hex}\nPayload (RAW)     : {pay_raw}\n"
            + "=" * 60
        )


def main():
    parser = argparse.ArgumentParser(description="Phylax Framework")
    parser.add_argument("target", nargs="?", help="Path to enterprise binary")
    parser.add_argument("--vector", choices=["stdin", "argv"], default="stdin")
    parser.add_argument("--size", type=int, default=1024)
    args = parser.parse_args()

    target = args.target if args.target else input("Target Binary Path: ").strip()
    if target:
        PhylaxEngine(target, payload_size=args.size).execute_triage(
            vector_type=args.vector
        )


if __name__ == "__main__":
    main()
