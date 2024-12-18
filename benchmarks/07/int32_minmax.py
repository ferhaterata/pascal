import angr
import archinfo
import claripy
from taint import Sensitive
import sca
import pascal

import logging
logging.getLogger(name='sca').setLevel(logging.INFO)

base_addr = 0x08000034
folder_name = './benchmarks/07/'
file_name = 'int32_minmax.o'
arch = archinfo.ArchARM(archinfo.Endness.BE)
# arch = archinfo.ArchARM(archinfo.Endness.BE, instruction_endness=archinfo.Endness.LE)
proj = angr.Project(folder_name + file_name, arch=arch,
                    load_options={"auto_load_libs": False, 'main_opts': {'base_addr': base_addr}})
func_name = 'test'
prototype = angr.types.parse_defns('void test(int32_t* a, int32_t* b);')[func_name]

a = claripy.BVS('a', 32, explicit_name=True).annotate(Sensitive())
b = claripy.BVS('b', 32, explicit_name=True).annotate(Sensitive())


addr = sca.getAddressOfSymbol(proj, func_name)
state: angr.SimState = proj.factory.call_state(
    addr, angr.PointerWrapper(a), angr.PointerWrapper(b), prototype=prototype)

simgr = proj.factory.simgr(state)

psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
    model=pascal.HammingWeight.basic)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingWeight.symba)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingWeight.obvbs)

# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingDistance.basic)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingDistance.symba)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.HammingDistance.obvbs)

# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.OmegaClassSampling.z3_basic)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.OmegaClassSampling.z3_bp)
# psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
#     model=pascal.OmegaClassSampling.cvc5_inc)


psca.arm(state)
vulnerabilities = psca.analyze(simgr)

sca.goto_vulnurablities(base_addr=base_addr, folder_name=folder_name, file_name=file_name,
                        func_name=func_name, vulnurebilities=vulnerabilities)

