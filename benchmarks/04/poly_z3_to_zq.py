import logging
import angr
import claripy
from taint import Sensitive
import sca
import pascal

import logging
logging.getLogger(name='sca').setLevel(logging.INFO)

base_addr = 0x08000034
folder_name = './benchmarks/04/'
file_name = 'poly_z3_to_zq.o'
proj = angr.Project(folder_name + file_name,
                    load_options={"auto_load_libs": False, 'main_opts': {'base_addr': base_addr}})
func_name = 'poly_Z3_to_Zq'
prototype = angr.types.parse_defns('void poly_Z3_to_Zq(struct poly {int16_t coeffs[509]; }*r);')[func_name]

coeffs = [claripy.BVS('coeff!{}'.format(i), 16, explicit_name=True).annotate(Sensitive()) for i in range(509)]
coeffs_symbolic = claripy.Concat(*coeffs)


addr = sca.getAddressOfSymbol(proj, func_name)
state: angr.SimState = proj.factory.call_state(addr,
                                               angr.PointerWrapper(coeffs_symbolic, buffer=True),
                                               prototype=prototype)
constraint = (claripy.Or(coeffs[0] == claripy.BVV(0x0, 16), coeffs[0] ==
              claripy.BVV(0x1, 16), coeffs[0] == claripy.BVV(0x2, 16)))
# constraint = None

simgr = proj.factory.simgr(state)

cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
print(proj.analyses.LoopFinder().loops)
loops = []
for loop in proj.analyses.LoopFinder().loops:
    print(f"{hex(loop.entry.addr)}")
    if hex(loop.entry.addr) in ('0x80000e4'):
        loops.append(loop)

simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg,
                                                         bound=0,
                                                         loops=loops,
                                                         functions=[func_name],
                                                         limit_concrete_loops=True))
simgr.use_technique(angr.exploration_techniques.DFS())

psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
    model=pascal.HammingWeight.basic, constraint=constraint)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingWeight.symba, constraint=constraint)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingWeight.obvbs, constraint=constraint)

# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingDistance.basic, constraint=constraint)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingDistance.symba, constraint=constraint)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingDistance.obvbs, constraint=constraint)

# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
# model=pascal.OmegaClassSampling.z3_basic, constraint=constraint)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.OmegaClassSampling.z3_bp, constraint=constraint)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.OmegaClassSampling.cvc5_inc, constraint=constraint)


psca.arm(state)
psca.analyze(simgr)
