#!/usr/bin/env python3
import angr
import claripy

# angr Project
proj = angr.Project("stateful.exe")

# Claripy Symbol
# From IDA, we know that the flag at most 43 bytes long
sym_arg = claripy.BVS("sym_arg", 43 * 8)
sym_arg = claripy.Concat(claripy.BVV(b"AIS3{"), sym_arg[5:])

# Create new program state
# entry_state := Program Entrypoint
state = proj.factory.entry_state(args=[proj.filename, sym_arg])
simgr = proj.factory.simulation_manager(state)

# simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=lambda s: b"Correct!!!" in s.posix.dumps(1))

# Extract state (if any)
found = simgr.found[0]
flag = found.solver.eval(sym_arg, cast_to=bytes)

print(flag)