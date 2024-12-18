import angr
import claripy
from taint import Sensitive
import sca
import pascal

import logging
logging.getLogger(name='sca').setLevel(logging.INFO)

base_addr = 0x08000034
folder_name = './benchmarks/14/'
file_name = 'frodo_key_encode.o'
proj = angr.Project(folder_name + file_name,
                    load_options={"auto_load_libs": False, 'main_opts': {'base_addr': base_addr}})
func_name = 'frodo_key_encode'
prototype = angr.types.parse_defns('void frodo_key_encode(uint16_t *out, const uint16_t *in);')[func_name]

out = [claripy.BVS('out!{}'.format(i), 16, explicit_name=True) for i in range(16)]
out_symbolic = claripy.Concat(*out)

in_ = [claripy.BVS('in!{}'.format(i), 16, explicit_name=True).annotate(Sensitive()) for i in range(64)]
in_symbolic = claripy.Concat(*in_)

addr = sca.getAddressOfSymbol(proj, func_name)
state: angr.SimState = proj.factory.call_state(addr,
                                               angr.PointerWrapper(out_symbolic, buffer=True),
                                               angr.PointerWrapper(in_symbolic, buffer=True),
                                               prototype=prototype)

simgr = proj.factory.simgr(state)

cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
print(proj.analyses.LoopFinder().loops)
loops = []
for loop in proj.analyses.LoopFinder().loops:
    print(f"{hex(loop.entry.addr)}")
    if hex(loop.entry.addr) in ('0x80001a0', '0x8000184', '0x8000108'):
        loops.append(loop)

simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg,
                                                         bound=7,
                                                         loops=loops,
                                                         functions=[func_name],
                                                         limit_concrete_loops=False))
simgr.use_technique(angr.exploration_techniques.DFS())

psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingWeight.basic)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingWeight.symba)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingWeight.obvbs)

# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingDistance.basic)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingDistance.symba)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingDistance.obvbs)

# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.OmegaClassSampling.z3_basic)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.OmegaClassSampling.z3_bp)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.OmegaClassSampling.cvc5_inc)

psca.arm(state)
vulnerabilities = psca.analyze(simgr)

sca.goto_vulnurablities(base_addr=base_addr, folder_name=folder_name, file_name=file_name,
                        func_name=func_name, vulnurebilities=vulnerabilities)
