import z3
import opt
import bv
import rel

import math

import cvc5.pythonic as cvc5
from typing import Dict, Tuple
from timeit import default_timer as timer
from scipy.stats import entropy
from multiprocessing.pool import ThreadPool
from copy import deepcopy

import logging
l = logging.getLogger(name='sca')
# l.addHandler(logging.StreamHandler())


def NoModel(*args):
    pass


def flag(*args):
    pass


def report(*args):
    pass


def Eta(eta: float) -> bool:
    return eta == 1.00 or eta <= 1.00


def DynamicAnalysis(*args):
    pass

def RegisterAnalysis(*args):
    pass

class HammingWeight:
    def basic(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.warning("--------------------------------------------")
        l.warning(f"{inst} (HammingWeight.basic)")
        l.warning("--------------------------------------------")
        width = expr.size()
        r, r_ = z3.BitVecs(f'{name} {name}\'', width)
        fml = r == expr
        fml_ = r_ == rel.self_compose(expr)[0]
        delta = bv.hw(r) - bv.hw(r_)

        start = timer()
        optimizer = z3.Optimize()
        optimizer.set(timeout=timeout*1000)
        improvement = []
        optimizer.set_on_model(lambda model: improvement.append(abs(model.eval(delta).as_long())))
        # optimizer.set_on_model(lambda model: l.debug(abs(model.eval(delta).as_long())))
        optimizer.add(fml)
        optimizer.add(fml_)
        optimizer.add(r != r_)
        optimizer.add(z3.UGE(delta, 0), z3.ULE(delta, r.size()))  # TODO: mention this in the paper
        if constraint is not None:
            optimizer.add(constraint)
        optimizer.push()
        optimizer.minimize(delta)
        min_w = -1
        max_w = -1
        memory_min = 0
        memory_max = 0
        if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.sat:
            min_w = abs(optimizer.model().eval(delta).as_long())
            l.warning("Minumum Hamming Weight Difference: {}".format(min_w))
            memory_min = float(optimizer.statistics().get_key_value('memory'))
        l.info(improvement)
        improvement = []
        optimizer.pop()
        if min_w != width:
            critical_value = None
            critical_value_ = None
            optimizer.push()
            optimizer.maximize(delta)
            if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.sat:
                max_w = abs(optimizer.model().eval(delta).as_long())
                critical_value = optimizer.model().eval(r).as_signed_long()
                critical_value_ = optimizer.model().eval(r_).as_signed_long()
                l.warning("Maximum Hamming Weight Difference: {}".format(max_w))
                memory_max = float(optimizer.statistics().get_key_value('memory'))
            l.info(improvement)
            l.warning("--------------------------------------------")
            optimizer.pop()
            if min_w == 1 and max_w == 1:
                optimizer.push()
                discriminant = z3.Extract(0, 0, r) ^ z3.Extract(0, 0, r_) != 1  # REVIEW
                optimizer.add(discriminant)
                if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.unsat:
                    flag(address, "vulnurable")
                    l.error("\033[94mThe solution space collapses into two values at {}!\033[0m".format(address))
                l.info(improvement)
                optimizer.pop()
            elif min_w == max_w and critical_value is not None and critical_value_ is not None:
                optimizer.push()
                optimizer.add(r != critical_value)
                optimizer.add(r_ != critical_value_)
                if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.unsat:
                    l.error("\033[94mCritical value detected: {} in ({}, {}) at {}!\033[0m".format(
                        name, critical_value, critical_value_, address))
                    flag(address, "vulnurable")
                optimizer.pop()
        else:
            max_w = min_w
            flag(address, "vulnurable")
            l.error("--------------------------------------------")
            l.error("\033[94mThe solution space collapses into two values at {}!\033[0m".format(address))

        # save the analysis results
        report(address, "max ω = {:<2} ∘ min ω = {:<2}".format(max_w, min_w))

        time = round(timer() - start, 4)
        memory = round(max(memory_min, memory_max), 2)
        l.warning(f" time = {time}, max-memory = {memory}")
        l.warning("--------------------------------------------")
        return time, memory

    def symba(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.warning("--------------------------------------------")
        l.warning(f"{inst} (HammingWeight.symba)")
        l.warning("--------------------------------------------")
        width = expr.size()
        r, r_ = z3.BitVecs(f'{name} {name}\'', width)
        fml = r == expr
        fml_ = r_ == rel.self_compose(expr)[0]
        delta = bv.hw(r) - bv.hw(r_)

        start = timer()
        optimizer = z3.Optimize()
        improvement = []
        optimizer.set_on_model(lambda model: improvement.append(abs(model.eval(delta).as_long())))
        optimizer.set(timeout=timeout*1000)
        optimizer.set("opt.optsmt_engine", 'symba')
        optimizer.add(fml)
        optimizer.add(fml_)
        optimizer.add(r != r_)
        optimizer.add(z3.UGE(delta, 0), z3.ULE(delta, r.size()))  # TODO: mention this in the paper
        if constraint is not None:
            optimizer.add(constraint)
        optimizer.push()
        optimizer.minimize(delta)
        min_w = -1
        max_w = -1
        memory_min = 0
        memory_max = 0
        if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.sat:
            min_w = abs(optimizer.model().eval(delta).as_long())
            l.warning("Minumum Hamming Weight Difference: {}".format(min_w))
            memory_min = float(optimizer.statistics().get_key_value('memory'))
        l.info(improvement)
        improvement = []
        optimizer.pop()
        if min_w != width:
            critical_value = None
            critical_value_ = None
            optimizer.push()
            optimizer.maximize(delta)
            if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.sat:
                max_w = abs(optimizer.model().eval(delta).as_long())
                critical_value = optimizer.model().eval(r).as_signed_long()
                critical_value_ = optimizer.model().eval(r_).as_signed_long()
                l.warning("Maximum Hamming Weight Difference: {}".format(max_w))
                memory_max = float(optimizer.statistics().get_key_value('memory'))
            l.info(improvement)
            l.warning("--------------------------------------------")
            optimizer.pop()
            if min_w == 1 and max_w == 1:
                optimizer.push()
                discriminant = z3.Extract(0, 0, r) ^ z3.Extract(0, 0, r_) != 1  # REVIEW
                optimizer.add(discriminant)
                if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.unsat:
                    flag(address, "vulnurable")
                    l.error("\033[94mThe solution space collapses into two values at {}!\033[0m".format(address))
                l.info(improvement)
                optimizer.pop()
            elif min_w == max_w and critical_value is not None and critical_value_ is not None:
                optimizer.push()
                optimizer.add(r != critical_value)
                optimizer.add(r_ != critical_value_)
                if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.unsat:
                    l.error("\033[94mCritical value detected: {} in ({}, {}) at {}!\033[0m".format(
                        name, critical_value, critical_value_, address))
                    flag(address, "vulnurable")
                optimizer.pop()
        else:
            max_w = min_w
            flag(address, "vulnurable")
            l.error("--------------------------------------------")
            l.error("\033[94mThe solution space collapses into two values at {}!\033[0m".format(address))

        # save the analysis results
        report(address, "max ω = {:<2} ∘ min ω = {:<2}".format(max_w, min_w))

        time = round(timer() - start, 4)
        memory = round(max(memory_min, memory_max), 2)
        l.warning(f" time = {time}, max-memory = {memory}")
        l.warning("--------------------------------------------")
        return time, memory

    def obvbs(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.warning(f"{address}:{inst}")
        l.warning("--------------------------------------------")
        width = expr.size()
        r, r_ = z3.BitVecs(f'{name} {name}\'', width)
        fml = r == expr
        fml_ = r_ == rel.self_compose(expr)[0]
        delta = bv.hw(r) - bv.hw(r_)

        start = timer()
        solver = z3.Optimize()
        solver.set("opt.optsmt_engine", 'symba')
        solver.add(fml)
        solver.add(fml_)
        solver.add(r != r_)
        w = z3.BitVec('w', delta.size())
        solver.add(w == delta)
        solver.add(z3.UGE(w, 0), z3.ULE(w, r.size()))
        if constraint is not None:
            solver.add(constraint)
        sexpr = solver.sexpr().replace('(check-sat)', '')
        min_model, max_model, solver_time, memory = opt.optimathsat(sexpr, timeout=timeout)
        max_w = -1
        min_w = -1
        if len(min_model) == 0 or len(max_model) == 0:
            l.error("min or max model is empty")
        else:
            bv.print_model(min_model, taint=[f'{name}', f'{name}\''])
            min_w = int(min_model["w"], 2)
            l.warning("Minumum Hamming Weight Difference: {}".format(min_w))
            bv.print_model(max_model, taint=[f'{name}', f'{name}\''])
            max_w = int(max_model["w"], 2)
            l.warning("Maximum Hamming Weight Difference: {}".format(max_w))
            if max_w == min_w:
                flag(address, "vulnurable")

        # save the analysis results
        report(address, "max ω = {:<2} ∘ min ω = {:<2}".format(max_w, min_w))

        time = round(timer() - start, 4)
        memory = round(memory, 2)
        l.warning(f" time = {time}, max-memory = {memory}")
        l.warning("--------------------------------------------")
        return time, memory


class HammingDistance:
    def basic(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.warning("--------------------------------------------")
        l.warning(f"{inst} (HammingDistance.basic)")
        l.warning("--------------------------------------------")
        width = expr.size()
        r, r_ = z3.BitVecs(f'{name} {name}\'', width)
        fml = r == expr
        fml_ = r_ == rel.self_compose(expr)[0]
        delta = bv.hd(r, r_)

        start = timer()
        optimizer = z3.Optimize()
        improvement = []
        optimizer.set_on_model(lambda model: improvement.append(abs(model.eval(delta).as_long())))
        optimizer.set(timeout=timeout*1000)
        optimizer.add(fml)
        optimizer.add(fml_)
        optimizer.add(r != r_)
        optimizer.add(z3.UGE(delta, 0), z3.ULE(delta, r.size()))
        if constraint is not None:
            optimizer.add(constraint)
        optimizer.push()
        optimizer.minimize(delta)
        memory_min = -1
        memory_max = -1
        min_w = -1
        if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.sat:
            min_w = abs(optimizer.model().eval(delta).as_long())
            l.warning("Minumum Hamming Distance: {}".format(min_w))
            memory_min = float(optimizer.statistics().get_key_value('memory'))
        l.info(improvement)
        improvement = []
        optimizer.pop()
        optimizer.push()
        optimizer.maximize(delta)
        max_w = -1
        if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.sat:
            max_w = abs(optimizer.model().eval(delta).as_long())
            l.warning("Maximum Hamming Distance: {}".format(max_w))
            memory_max = float(optimizer.statistics().get_key_value('memory'))
        l.info(improvement)
        l.warning("--------------------------------------------")
        optimizer.pop()

        # save the analysis results
        report(address, "max d = {:<2} ∘ min d = {:<2}".format(max_w, min_w))

        if max_w == min_w:
            flag(address, "vulnurable")

        time = round(timer() - start, 4)
        memory = round(max(memory_min, memory_max), 2)
        l.warning(f" time = {time}, max-memory = {memory}")
        l.warning("--------------------------------------------")
        return time, memory

    def symba(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.warning("--------------------------------------------")
        l.warning(f"{inst} (HammingDistance.symba)")
        l.warning("--------------------------------------------")
        width = expr.size()
        r, r_ = z3.BitVecs(f'{name} {name}\'', width)
        fml = r == expr
        fml_ = r_ == rel.self_compose(expr)[0]
        delta = bv.hd(r, r_)
        start = timer()
        optimizer = z3.Optimize()
        improvement = []
        optimizer.set_on_model(lambda model: improvement.append(abs(model.eval(delta).as_long())))
        optimizer.set(timeout=timeout*1000)
        optimizer.set("opt.optsmt_engine", 'symba')
        optimizer.add(fml)
        optimizer.add(fml_)
        optimizer.add(r != r_)
        optimizer.add(z3.UGE(delta, 0), z3.ULE(delta, r.size()))
        if constraint is not None:
            optimizer.add(constraint)
        optimizer.push()
        optimizer.minimize(delta)
        memory_min = -1
        memory_max = -1
        min_w = -1
        if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.sat:
            min_w = abs(optimizer.model().eval(delta).as_long())
            l.warning("Minumum Hamming Distance: {}".format(min_w))
            memory_min = float(optimizer.statistics().get_key_value('memory'))
        l.info(improvement)
        improvement = []
        optimizer.pop()
        optimizer.push()
        optimizer.maximize(delta)
        max_w = -1
        if bv.model(optimizer, taint=[f'{name}', f'{name}\'']) == z3.sat:
            max_w = abs(optimizer.model().eval(delta).as_long())
            l.warning("Maximum Hamming Distance: {}".format(max_w))
            memory_max = float(optimizer.statistics().get_key_value('memory'))
        l.info(improvement)
        l.warning("--------------------------------------------")
        optimizer.pop()

        # save the analysis results
        report(address, "max d = {:<2} ∘ min d = {:<2}".format(max_w, min_w))

        if max_w == min_w:
            flag(address, "vulnurable")

        time = round(timer() - start, 4)
        memory = round(max(memory_min, memory_max), 2)
        l.warning(f" time = {time}, max-memory = {memory}")
        l.warning("--------------------------------------------")
        return time, memory

    def obvbs(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.warning("--------------------------------------------")
        l.warning(f"{inst} (HammingDistance.obvbs)")
        l.warning("--------------------------------------------")
        width = expr.size()
        r, r_ = z3.BitVecs(f'{name} {name}\'', width)
        fml = r == expr
        r_ = z3.BitVec('r\'', width)
        b_ = z3.BitVec('b\'', width)
        fml_ = r_ == rel.self_compose(expr)[0]
        delta = bv.hd(r, r_)

        start = timer()
        solver = z3.Optimize()
        solver.set("opt.optsmt_engine", 'symba')
        solver.add(fml)
        solver.add(fml_)
        solver.add(r != r_)
        w = z3.BitVec('w', delta.size())
        solver.add(w == delta)
        solver.add(z3.UGE(w, 0), z3.ULE(w, r.size()))
        if constraint is not None:
            solver.add(constraint)
        sexpr = solver.sexpr().replace('(check-sat)', '')
        min_model, max_model, solver_time, memory = opt.optimathsat(sexpr, timeout=timeout)
        max_w = -1
        min_w = -1
        if len(min_model) == 0 or len(max_model) == 0:
            l.error("min or max model is empty")
        else:
            bv.print_model(min_model, taint=[f'{name}', f'{name}\''])
            min_w = int(min_model["w"], 2)
            l.warning("Minumum Hamming Distance: {}".format(min_w))
            bv.print_model(max_model, taint=[f'{name}', f'{name}\''])
            max_w = int(max_model["w"], 2)
            l.warning("Maximum Hamming Distance: {}".format(max_w))
            l.warning("--------------------------------------------")
            if max_w == min_w:
                flag(address, "vulnurable")

        # save the analysis results
        report(address, "max ω = {:<2} ∘ min ω = {:<2}".format(max_w, min_w))

        time = round(timer() - start, 4)
        memory = round(memory, 2)
        l.warning(f" time = {time}, max-memory = {memory}")
        l.warning("--------------------------------------------")
        return time, memory


class OmegaClassSampling:

    def probs(width, classes):
        probs = []
        domain = 2**width
        for i in range(len(classes)):
            combination = math.comb(width, i)
            probs.append(combination/domain)
        return probs

    def z3_basic(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", model=True, constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.warning("--------------------------------------------")
        l.warning(f"{inst} (OmegaClassSampling.z3_basic)")
        l.warning("--------------------------------------------")
        width = expr.size()

        z3.set_option("parallel.enable", True)
        z3.set_option("parallel.threads.max", 8)
        # z3.set_option("sat.threads", 2)
        # z3.set_option("sat.local_search_threads", 2)
        # z3.set_option("sat.lookahead_simplify", True)

        # print(z3.get_param('sat.local_search_threads'))

        def omega_sampling():
            size = expr.size()+1
            classes = []
            models = [''] * (size)
            memory = 0
            start = timer()
            s = z3.SolverFor("QF_FD")
            if constraint is not None:
                s.add(constraint)
            # s = z3.SolverFor("QF_BV")
            s.set(timeout=timeout*1000)
            for i in range(size):
                fml = bv.hw(expr) == i
                fml = z3.simplify(fml)
                s.push()
                s.add(fml)
                if s.check() == z3.sat:
                    classes.append(1)
                    if model:
                        models[i] = bv.eval(s.model(), expr, name=name)
                else:
                    classes.append(0)
                memory = max(memory, float(s.statistics().get_key_value('memory')))
                s.pop()
                s.add(z3.Not(fml))
            time = round(timer() - start, 4)
            return classes, models, time, memory

        classes, models, time, memory = omega_sampling()

        scales = OmegaClassSampling.probs(width, classes)
        # l.debug(["{:.2e}".format(w) for w in scales])
        # l.debug("--------------------------------------------")

        for i in range(len(classes)):
            if classes[i] == 1:
                l.info("{:<5}={} : {}".format(f"w({i})", classes[i], models[i]))
        l.info("--------------------------------------------")

        eta = entropy([a * b for a, b in zip(scales, classes)], base=2)
        l.warning("entropy= %f" % eta)
        l.warning("--------------------------------------------")

        # save the analysis results
        report(address, "η = {:0.8f}".format(eta))

        if Eta(eta):
            flag(address, "vulnurable")

        time = round(time, 4)
        memory = round(memory, 2)
        l.warning(f" time = {time}, max-memory = {round(memory, 2)}")
        l.warning("--------------------------------------------")
        return time, memory

    def z3_parallel(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", model=True, constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.warning("--------------------------------------------")
        l.warning(f"{inst} (OmegaClassSampling.z3_parallel)")
        l.warning("--------------------------------------------")
        width = expr.size()

        assert expr.ctx == z3.main_ctx()

        pool = ThreadPool(4)
        start = timer()

        classes = {}
        models = {}

        def calculate(expr, n, ctx):
            """ Do a simple computation with a context"""
            assert expr.ctx == ctx
            assert expr.ctx != z3.main_ctx()
            # Parallel creation of z3 object
            fml = bv.hw(expr) == n
            # Parallel solving
            s = z3.Solver(ctx=ctx)
            s.set(timeout=timeout*1000)
            s.add(fml)
            result = s.check()
            if result == z3.sat:
                # print(n, "sat")
                if model:
                    models[n] = bv.eval(s.model(), expr, name)
                classes[n] = 1
            elif result == z3.unsat:
                # print(n, ":unsat")
                classes[n] = 0
            else:
                # if s.reason_unknown() == 'timeout':
                #     print(n, s.reason_unknown())
                # else:
                #     print(n, "unknown")
                classes[n] = 0

        for i in range(expr.size()+1):
            # Create new context for the computation
            # Note that we need to do this sequentially, as parallel access to the current context or its objects
            # will result in a segfault
            i_context = z3.Context()
            expr_i = deepcopy(expr).translate(i_context)

            # Kick off parallel computation
            pool.apply_async(calculate, [expr_i, i, i_context])

        pool.close()
        pool.join()

        time = round(timer() - start, 4)

        scales = OmegaClassSampling.probs(width, classes)
        # l.debug(["{:.2e}".format(w) for w in scales])
        # l.debug("--------------------------------------------")

        for i in range(len(classes)):
            if classes[i] == 1:
                l.info("{:<5}={} : {}".format(f"w({i})", classes[i], models.get(i, "unsat")))
        l.info("--------------------------------------------")

        eta = entropy([a * b for a, b in zip(scales, classes)], base=2)
        l.warning("entropy= %f" % eta)
        l.warning("--------------------------------------------")

        # save the analysis results
        report(address, "η = {:0.8f}".format(eta))

        if Eta(eta):
            flag(address, "vulnurable")

        time = round(time, 4)
        l.warning(f" time = {time}")
        l.warning("--------------------------------------------")
        return time, 0

    def z3_bp(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", model=True, constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.warning("--------------------------------------------")
        l.warning(f"{inst} (OmegaClassSampling.z3_bp)")
        l.warning("--------------------------------------------")
        width = expr.size()

        def omega_sampling():
            size = expr.size()+1
            classes = []
            models = [''] * (size)
            memory = 0
            start = timer()
            s = z3.SolverFor("QF_FD")
            s.set(timeout=timeout*1000)
            # s.set("sat.pb.solver", "solver")
            z3.set_option("parallel.enable", True)
            z3.set_option("parallel.threads.max", 8)
            if constraint is not None:
                s.add(constraint)
            for i in range(size):
                fml = bv.hw_eq(expr, i)
                fml = z3.simplify(fml)
                s.push()
                s.add(fml)
                if s.check() == z3.sat:
                    classes.append(1)
                    if model:
                        models[i] = bv.eval(s.model(), expr)
                else:
                    classes.append(0)
                memory = max(memory, float(s.statistics().get_key_value('memory')))
                s.pop()
                s.add(z3.Not(fml))
            time = round(timer() - start, 4)
            return classes, models, time, memory

        classes, models, time, memory = omega_sampling()

        scales = OmegaClassSampling.probs(width, classes)
        # l.debug(["{:.2e}".format(w) for w in scales])
        # l.debug("--------------------------------------------")

        for i in range(len(classes)):
            if classes[i] == 1:
                l.info("{:<5}={} : {}".format(f"w({i})", classes[i], models[i]))
        l.info("--------------------------------------------")

        eta = entropy([a * b for a, b in zip(scales, classes)], base=2)
        l.warning("entropy= %f" % eta)
        l.warning("--------------------------------------------")

        # save the analysis results
        report(address, "η = {:0.8f}".format(eta))

        if eta <= 1.00:
            flag(address, "vulnurable")

        time = round(time, 4)
        memory = round(memory, 2)
        l.warning(f" time = {time}, max-memory = {round(memory, 2)}")
        l.warning("--------------------------------------------")
        return time, memory

    def cvc5_inc(expr: z3.BitVecRef, name: str, address: str, inst="<inst>", model=True, constraint=None, flag=flag, report=report, timeout=1200) -> Tuple[float, float]:
        l.debug("--------------------------------------------")
        l.debug(expr.sexpr())
        l.debug("--------------------------------------------")
        expr = bv.to_cvc5(expr)
        constraint = bv.to_cvc5(constraint)
        l.debug(expr.sexpr())
        l.warning("--------------------------------------------")
        l.warning(f"{inst} (OmegaClassSampling.cvc5_inc)")
        l.warning("--------------------------------------------")
        width = expr.size()

        def omega_sampling():
            """It seems CVC5 does not provide a way to get memory usage"""
            size = expr.size()+1
            classes = []
            models = [''] * (size)
            start = timer()
            s = cvc5.Solver()
            if not s.getOption("incremental"):
                s.setOption(incremental='true')
            # if not s.getOption('tlimit'):
            #     s.setOption(tlimit=timeout*1000)
            if not s.getOption('tlimit-per'):
                s.setOption('tlimit-per', timeout*1000)
            if constraint is not None:
                s.add(constraint)
            for i in range(size):
                fml = bv.hw_cvc5(expr) == i
                fml = cvc5.simplify(fml)
                s.push()
                s.add(fml)
                if s.check() == z3.sat:
                    classes.append(1)
                    if model:
                        models[i] = bv.eval(s.model(), expr, name)
                else:
                    classes.append(0)
                s.pop()
                s.add(cvc5.Not(fml))
            time = round(timer() - start, 4)
            return classes, models, time

        classes, models, time = omega_sampling()

        scales = OmegaClassSampling.probs(width, classes)
        l.debug(["{:.2e}".format(w) for w in scales])
        l.debug("--------------------------------------------")

        for i in range(len(classes)):
            if classes[i] == 1:
                l.info("{:<5}={} : {}".format(f"w({i})", classes[i], models[i]))
        l.info("--------------------------------------------")

        eta = entropy([a * b for a, b in zip(scales, classes)], base=2)
        l.warning("entropy= %f" % eta)
        l.warning("--------------------------------------------")

        # save the analysis results
        report(address, "η = {:0.8f}".format(eta))

        if Eta(eta):
            flag(address, "vulnurable")

        time = round(time, 4)
        l.warning(f" time = {time}")
        l.warning("--------------------------------------------")
        return time, 0
