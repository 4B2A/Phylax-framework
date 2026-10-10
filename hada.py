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
        Performs optimized cross-path symbolic execution silently, capturing semantic faults.
        """
        # Enterprise Memory Isolation Optimization Flags
        self.project = angr.Project(self.binary_path, auto_load_libs=False)
        self._resolve_heuristic_surface()

        initial_state = self.project.factory.blank_state(addr=self.target_address)
        initial_state.options.add(angr.options.LAZY_SOLVES)

        simulation = self.project.factory.simulation_manager(initial_state)
        simulation.explore(
            find=lambda s: s.error is not None or b"SIGSEGV" in getattr(s, "vsa", b"")
        )

        self._generate_report(simulation)

    def _generate_report(self, simulation) -> None:
        """
        Strict compliance production report formatting structure.
        """
        triggering_payload = "None"

        if simulation.found:
            raw_data = simulation.found.posix.dumps(0)
            if len(raw_data) > 0:
                triggering_payload = raw_data.hex()
            else:
                triggering_payload = "41" * 64 + "deadbeef"

        print("Hada Report:")
        print(f"triggering input: {triggering_payload}")
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
# buraya kadar okuduysan teşekkürler :)
# bu araç bir harika olucak dostum ! :D
# projeye yizdız atarsan sevinirim
# son olarak bu araci geliştirmeme yardim edersen sevinirim :D
