import angr
import claripy
from taint import Sensitive
import sca
import pascal

import logging
logging.getLogger(name='sca').setLevel(logging.INFO)


proj = angr.Project('./benchmarks/08/int32_minmax.o',
                    load_options={"auto_load_libs": True, 'main_opts': {'base_addr': 0x08000034}})
func = 'test'
ty = angr.types.parse_defns('void test(int32_t* a, int32_t* b);')[func]
cc = proj.factory.cc(func_ty=ty)  # new calling convention

a = claripy.BVS('a', 32, explicit_name=True).annotate(Sensitive())
b = claripy.BVS('b', 32, explicit_name=True).annotate(Sensitive())


addr = sca.getAddressOfSymbol(proj, func)
state: angr.SimState = proj.factory.call_state(addr, angr.PointerWrapper(a), angr.PointerWrapper(b), cc=cc)

simgr = proj.factory.simgr(state)

# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingWeight.basic)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingWeight.symba)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingWeight.obvbs)

# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingDistance.basic)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingDistance.symba)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.HammingDistance.obvbs)

# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.OmegaClassSampling.z3_basic)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.OmegaClassSampling.z3_bp)
psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(model=pascal.OmegaClassSampling.cvc5_inc)

psca.arm(state)
psca.analyze(simgr)