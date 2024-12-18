import random
import angr
import claripy
from taint import Sensitive
import sca
import pascal

import logging
logging.getLogger(name='sca').setLevel(logging.INFO)


proj = angr.Project('./benchmarks/00/add.o', load_debug_info=False,
                    load_options={"auto_load_libs": False, 'main_opts': {'base_addr': 0x08000034}})
func = 'add'
prototype = angr.types.parse_defns('int16_t add(int16_t a);')[func]
print(prototype)
addr = sca.getAddressOfSymbol(proj, func)


def random_bits(word_size, hamming_weight):
    number = 0
    for bit in random.sample(range(word_size), hamming_weight):
        number |= 1 << bit
    return number


# generate 100 random inputs
word_size = 16
hamming_weight = 3
inputs = [claripy.BVV(random_bits(word_size, hamming_weight), word_size).annotate(Sensitive()) for _ in range(3)]

concrete_values = {}
for i in inputs:
    state: angr.SimState = proj.factory.call_state(addr, i, prototype=prototype)
    simgr = proj.factory.simgr(state)
    # cfg = proj.analyses.CFGFast(normalize=True)
    # simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=5))
    psca: sca.PowerSideChannelAnalysis = proj.analyses.PowerSideChannelAnalysis(
        model=pascal.DynamicAnalysis, concrete_values=concrete_values)
    psca.arm(state)
    psca.analyze(simgr)
    print('concrete values: ')
    for k, v in concrete_values.items():
        print(k, v)

