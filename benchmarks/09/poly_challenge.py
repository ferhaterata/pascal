import logging
import angr
import claripy
from taint import Sensitive
import sca
import pascal
logging.getLogger(name='sca').setLevel(logging.INFO)

base_addr = 0x08000034
folder_name = './benchmarks/09/'
file_name = 'poly_challenge.o'
proj = angr.Project(folder_name + file_name,
                    load_options={"auto_load_libs": False, 'main_opts': {'base_addr': base_addr}})
func_name = 'poly_challenge'
prototype = angr.types.parse_defns(
    'void poly_challenge(struct poly {int16_t coeffs[256]; }*c, const uint8_t *seed);')[func_name]
# 'void poly_challenge(struct poly {int16_t coeffs[256]; }*c, const uint8_t seed[32]);')[func]

c = [claripy.BVS('c!{}'.format(i), 16, explicit_name=True).annotate(Sensitive()) for i in range(256)]
c_sym = claripy.Concat(*c)

seed = [claripy.BVS('seed!{}'.format(i), 8, explicit_name=True).annotate(Sensitive()) for i in range(32)]
seed_sym = claripy.Concat(*seed)

addr = sca.getAddressOfSymbol(proj, func_name)
state: angr.SimState = proj.factory.call_state(addr,
                                               angr.PointerWrapper(c_sym, buffer=True),
                                               angr.PointerWrapper(seed_sym, buffer=True),
                                               prototype=prototype)

binary_addr_range = set(range(0x08000034, 0x0800457c, 4))
poly_chall_addr = set(range(0x080042c4, 0x080044bc, 4))
# shake256_init = list(range(0x08004080, 0x080040a4, 4))
# keccak_init = list(range(0x08004014, 0x0800402c, 4))

simgr = proj.factory.simgr(state)


cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
print(proj.analyses.LoopFinder().loops)
loops = []
for loop in proj.analyses.LoopFinder().loops:
    print(f"{hex(loop.entry.addr)}")
    if hex(loop.entry.addr) in ('0x80043e4', '0x800440c'):
        loops.append(loop)

simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg,
                                                         bound=2,
                                                         loops=loops,
                                                         functions=[func_name],
                                                         limit_concrete_loops=True))
simgr.use_technique(angr.exploration_techniques.DFS())


psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
    model=pascal.HammingWeight.basic, exclude=list(binary_addr_range.difference(poly_chall_addr)))

psca.arm(state)
vulnerabilities = psca.analyze(simgr)

sca.goto_vulnurablities(base_addr=base_addr, folder_name=folder_name, file_name=file_name,
                        func_name=func_name, vulnurebilities=vulnerabilities)
