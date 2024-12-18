import angr
import claripy
from taint import Sensitive
import sca
import pascal

import logging
logging.getLogger(name='sca').setLevel(logging.INFO)

base_addr = 0x08000034
folder_name = './benchmarks/19/'
file_name = '2021-1307_2.o'
proj = angr.Project(folder_name + file_name,
                    load_options={"auto_load_libs": False, 'main_opts': {'base_addr': base_addr}})
func_name = 'poly_frommsg'
prototype = angr.types.parse_defns(
    'void poly_frommsg(struct poly {char coeffs[256]; }* r, const uint8_t* msg);')[func_name]

coeffs = [claripy.BVS('coeff!{}'.format(i), 16, explicit_name=True) for i in range(256)]
coeffs_symbolic = claripy.Concat(*coeffs)

msg = [claripy.BVS('msg!{}'.format(i), 8, explicit_name=True).annotate(Sensitive()) for i in range(32)]
msg_symbolic = claripy.Concat(*msg)

addr = sca.getAddressOfSymbol(proj, func_name)
state: angr.SimState = proj.factory.call_state(addr,
                                               angr.PointerWrapper(coeffs_symbolic, buffer=True),
                                               angr.PointerWrapper(msg_symbolic, buffer=True),
                                               prototype=prototype)

simgr = proj.factory.simgr(state)

cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
print(proj.analyses.LoopFinder().loops)
loops = []
for loop in proj.analyses.LoopFinder().loops:
    print(f"{hex(loop.entry.addr)}")
    if hex(loop.entry.addr) in ('0x8000128', '0x8000140'):
        loops.append(loop)

simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg,
                                                         bound=7,
                                                         loops=loops,
                                                         functions=[func_name],
                                                         limit_concrete_loops=True))
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
