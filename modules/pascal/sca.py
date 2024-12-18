import enum
import os
import sys
import angr
import capstone
import claripy
import pyvex
import re
import z3
import pickle
from timeit import default_timer as timer
from typing import List, Set, Dict, Tuple, Optional


from taint import is_sensitive
import rel
import bv
import mc
import opt
import pascal

import logging
l = logging.getLogger(name='sca')
# logging.getLogger(name='sca').setLevel(logging.INFO)


class PowerSideChannelAnalysis(angr.Analysis):

    def __init__(self, model=pascal.HammingWeight.basic, constraint=None,
                 register_expression: Dict[str, List[int]] = None,
                 concrete_values: Dict[str, List[int]] = None, exclude=[]):
        """
        :param model: model function to use 
        :param exclude: list of address intervals to exclude from analysis
        """
        SCA.model = model
        SCA.constraint = constraint
        SCA.excluded_addresses = exclude
        SCA._concrete_values = concrete_values
        SCA._register_expression = register_expression
        self._start_addr = None

    def arm(self, state: angr.SimState, trace=True):
        state.register_plugin('sca', SCA(trace=trace))
        self._start_addr = state.addr
        state.sca.arm(state)

    def analyze(self, simgr: angr.SimulationManager, reproducible=False):

        def _write(start):
            elapsed = str(round(timer() - start, 3))
            l.warning("Elapsed Time: {} seconds.".format(elapsed))  # Time in seconds

            # commands = ["o {}\n".format(self.project.filename), "aaa\n", *SCA.r2_script_model()]
            commands = ["aaa\n", *SCA.r2_script_model()]
            r2_file = self.project.filename + ".r2"
            if os.path.exists(r2_file):
                os.remove(r2_file)
            with open(r2_file, 'a') as r2_script:
                r2_script.write(''.join(commands))
                addr = hex(self._start_addr-1) if self.project.arch.is_thumb(self._start_addr) else hex(self._start_addr)
                r2_script.write('f t:{}sec @ {}\n'.format(elapsed, addr))
                r2_script.write("pdf\n")

            if reproducible:
                queries = '   '.join(SCA.py_query_script())
                reproducible_queries = self.project.filename + ".py"
                if os.path.exists(reproducible_queries):
                    os.remove(reproducible_queries)
                with open(reproducible_queries, 'a') as py_script:
                    py_script.write('import pickle\n\n')
                    py_script.write('queries = {{\n   {}}}\n\n'.format(queries))
                    py_script.write('for k, v in queries.items(): print(f"{hex(k)} -> {pickle.loads(v)}")')

            return elapsed

        start = timer()

        # simgr.explore(find=0x80005fc)
        # if simgr.found:
        #     print()
        elapsed = None
        try:
            while simgr.active:
                # for i in range(0, len(simgr.active)):
                # state = simgr.active[i]
                # l.info("==========================================================")
                # l.info("Fork at {}".format(hex(state.addr)))
                # l.info("==========================================================")
                # l.info("Constraints: ")
                # l.info("----------------------------------------------------------")
                # for c in state.solver.constraints:
                #     fml = claripy.backends.z3.convert(c)
                #     l.info(fml)
                simgr.step()
                # simgr.step(num_inst=1)
            elapsed = _write(start)
        except KeyboardInterrupt:
            print()
            l.warning('Interrupted by the user.')
            try:
                elapsed = _write(start)
                sys.exit(0)
            except SystemExit:
                os._exit(0)
        return SCA._radare2_flags.keys()


# register the class with angr's global analysis list
angr.AnalysesHub.register_default('PowerSideChannelAnalysis', PowerSideChannelAnalysis)

shift_signature_re = re.compile(r'Iop_(Shl|Shr|Sar)(?P<size>\d+)$')
not_signature_re = re.compile(r'Iop_(Not|Ctz|Clz)(?P<size>\d+)$')
xor_or_signature_re = re.compile(r'Iop_(Xor|Or)(?P<size>\d+)$')
and_signature_re = re.compile(r'Iop_And(?P<size>\d+)$')
sub_signature_re = re.compile(r'Iop_Sub(?P<size>\d+)$')
add_signature_re = re.compile(r'Iop_Add(?P<size>\d+)$')


class SCA(angr.SimStatePlugin):
    """
    State tracking for Power Side-Channel vulnerability detection.
    """
    # configuration parameters
    model = pascal.NoModel
    constraint = None
    excluded_addresses = None
    # to serialize the analysis for radare 2
    _counter = 0
    # tainted formula generated at a specific instruction address
    _reproducible_queries = {}
    # omegas generated at a specific instruction address
    _radare2_models: Dict[str, List[str]] = {}
    # flags
    _radare2_flags = {}
    _vulnurability_counter = 0

    _concrete_values: Dict[str, List[int]] = {}

    # to track the expression to be analyzed for each instruction.
    _last_wrtmp_expr = None
    _last_wrtmp_inst: Tuple[str, str, str, str] = None
    _last_inst: Tuple[str, str, str] = None

    def __init__(self, armed=False, trace=False):
        super().__init__()
        self._trace = trace
        self.uid = self.uniqueId()
        self._armed = armed
        self.vex = None

    @classmethod
    def uniqueId(cls):
        cls._counter += 1
        return cls._counter

    @classmethod
    def _py_query(cls, addr, query):
        if addr not in cls._reproducible_queries:
            cls._reproducible_queries[addr] = query

    @classmethod
    def _r2_model(cls, addr: str, model: str):
        if addr not in cls._radare2_models:
            cls._radare2_models[addr] = [model]
        else:
            cls._radare2_models[addr].append(model)

    @classmethod
    def _r2_flag(cls, addr, flag):
        if addr not in cls._radare2_flags:
            cls._radare2_flags[addr] = '{}_{}'.format(flag, cls._vulnurability_counter)
            cls._vulnurability_counter += 1

    @classmethod
    def r2_script(cls) -> list:
        """
        Return a radare2 script which will be run on the binary to
        show the vulnurable instructions and their symbolic formulas
        """
        comments = ['s {}; CC+ {}\n'.format(k, str(v)
                                            .replace('\n', '\\n')).replace('>', '\>', 1)
                    .replace('|', '\|') for k, v in cls._radare2_comments.items()]
        flags = ['f {} @ {}\n'.format(v, k) for k, v in cls._radare2_flags.items()]
        return [*comments, *flags]

    @classmethod
    def py_query_script(cls) -> list:
        """
        Return a reproduciability script which will be run the queries 
        """
        scripts = ['{}: {},\n'.format(k, v) for k, v in cls._reproducible_queries.items()]
        return scripts

    @classmethod
    def r2_script_model(cls) -> list:
        """
        Return a radare2 script which will be run on the binary that
        provides the symbolic model for each secret tainted instruction execution.
        """
        models = ['s {}; CC+ {}\n'.format(k, " │ ".join(lst)) for k, lst in cls._radare2_models.items()]
        flags = ['f {} @ {}\n'.format(v, k) for k, v in cls._radare2_flags.items()]
        return [*models, *flags]

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        copied = SCA()
        copied.vex = self.vex
        if self._trace:
            l.info("new state state{} copied from state{}".format(copied.uid, self.uid))
        return copied

    def arm(self, state: angr.SimState):
        if self._armed:
            l.warning("called arm() on already-armed Power SCA state")
            return

        if self._trace:
            # TODO: add here normal memory read/write/...
            pass

        state.inspect.b('instruction', when=angr.BP_BEFORE, action=analyze_instr)
        # state.inspect.b('instruction', when=angr.BP_AFTER, action=analyze_snapshot)
        state.inspect.b('irsb', when=angr.BP_BEFORE, action=analyze_irsb)
        state.inspect.b('statement', when=angr.BP_AFTER, action=analyze_stmt)
        state.inspect.b('tmp_write', when=angr.BP_AFTER, action=analyze_tmp_write)
        state.inspect.b('reg_write', when=angr.BP_AFTER, action=analyze_reg_write)  # SCA happens here

        state.inspect.b('mem_read', when=angr.BP_AFTER, condition=_tainted_read, action=detected_memory_read)
        state.inspect.b('mem_write', when=angr.BP_AFTER, condition=_tainted_write, action=detected_memory_write)
        state.inspect.b('exit', when=angr.BP_BEFORE, condition=_tainted_branch, action=detected_memory_branch)

        # state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        # state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

        # state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
        # state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)

        state.options.add(angr.options.LAZY_SOLVES)
        state.options.add(angr.options.UNICORN)
        state.options.remove(angr.options.SIMPLIFY_MEMORY_WRITES)  # TODO: choose simplification strategy later
        state.options.remove(angr.options.SIMPLIFY_REGISTER_WRITES)
        # state.options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
        # state.options.add(angr.options.SIMPLIFY_MEMORY_READS)
        # state.options.add(angr.options.SIMPLIFY_REGISTER_WRITES)
        # state.options.add(angr.options.SIMPLIFY_REGISTER_READS)

        self._armed = True

    def armed(self):
        """
        Has arm() been called?
        """
        return self._armed


def taint(ast, checkTaint=True) -> str:
    if isinstance(ast, angr.state_plugins.sim_action_object.SimActionObject):  # HACK
        ast = ast.ast

    return "" if not isinstance(ast, claripy.ast.Base) \
        else "" if not checkTaint \
        else " (sensitive)" if is_sensitive(ast) \
        else " (tainted: {})".format(ast, ast.annotations) if hasattr(ast, 'annotations') and ast.annotations \
        else ""  # (untainted)


def address(state: angr.SimState) -> str:
    return state.inspect.instruction-1 if state.project.arch.is_thumb(state.inspect.instruction) \
        else state.inspect.instruction


def machine_inst(hex_addr, inst_mnemonic, inst_op_str) -> str:
    return '{}:  {}   {}'.format(hex_addr, inst_mnemonic, inst_op_str)


def analyze_irsb(state: angr.SimState) -> None:
    # print(state.block().vex.pp())
    state.sca.vex = state.block().vex


def analyze_tmp_write(state: angr.SimState) -> None:
    expr = state.inspect.tmp_write_expr
    inZ3 = claripy.backends.z3.convert(expr)
    l.info('t{}{} == \033[33m{}\033[0m'.format(state.inspect.tmp_write_num, taint(expr), inZ3))

    # TODO: something weird happens when the statement is not in the block
    if state.inspect.statement >= len(state.sca.vex.statements):
        l.info('state{}: \033[0m{}'.format(state.sca.uid, "Vex stmt is not in the IR!!!!"))
        return

    if SCA.model is not pascal.NoModel and address(state) not in SCA.excluded_addresses:
        stms = state.sca.vex.statements
        vex_stmt = stms[state.inspect.statement]
        capstoneBlock: angr.block.DisassemblerBlock = state.block().capstone
        n = state.block().instruction_addrs.index(state.inspect.instruction)
        insn: angr.block.CapstoneInsn = capstoneBlock.insns[n]
        if hasattr(vex_stmt, 'data') and isinstance(vex_stmt.data, pyvex.expr.Binop):
            if is_sensitive(expr):  # is tainted?
                if shift_signature_re.match(vex_stmt.data.op):
                    SCA._last_wrtmp_inst = (hex(address(state)), insn.mnemonic, insn.op_str, arm_Rd_name(insn))
                    SCA._last_wrtmp_expr = state.inspect.tmp_write_expr
                if xor_or_signature_re.match(vex_stmt.data.op):
                    SCA._last_wrtmp_inst = (hex(address(state)), insn.mnemonic, insn.op_str, arm_Rd_name(insn))
                    SCA._last_wrtmp_expr = state.inspect.tmp_write_expr
                if and_signature_re.match(vex_stmt.data.op):
                    SCA._last_wrtmp_inst = (hex(address(state)), insn.mnemonic, insn.op_str, arm_Rd_name(insn))
                    SCA._last_wrtmp_expr = state.inspect.tmp_write_expr
                if sub_signature_re.match(vex_stmt.data.op):
                    SCA._last_wrtmp_inst = (hex(address(state)), insn.mnemonic, insn.op_str, arm_Rd_name(insn))
                    SCA._last_wrtmp_expr = state.inspect.tmp_write_expr
                if add_signature_re.match(vex_stmt.data.op):
                    SCA._last_wrtmp_inst = (hex(address(state)), insn.mnemonic, insn.op_str, arm_Rd_name(insn))
                    SCA._last_wrtmp_expr = state.inspect.tmp_write_expr
        elif hasattr(vex_stmt, 'data') and isinstance(vex_stmt.data, pyvex.expr.Unop):
            if is_sensitive(expr):  # is tainted?
                if not_signature_re.match(vex_stmt.data.op):
                    SCA._last_wrtmp_inst = (hex(address(state)), insn.mnemonic, insn.op_str, arm_Rd_name(insn))
                    SCA._last_wrtmp_expr = state.inspect.tmp_write_expr


def arm_Rd_name(instruction: angr.block.CapstoneInsn) -> str:
    """return the name of the destination register name"""
    insn: capstone.CsInsn = instruction.insn
    i = insn.operands[0]
    if i.type == capstone.arm.ARM_OP_REG:
        return insn.reg_name(i.reg)
    return "Rd"


def analyze_stmt(state: angr.SimState) -> None:

    # TODO: something weird happens when the statement is not in the block
    if state.inspect.statement >= len(state.sca.vex.statements):
        l.info('state{}: \033[0m{}'.format(state.sca.uid, "Vex stmt is not in the IR!!!!"))
        return

    stmt = state.sca.vex.statements[state.inspect.statement]
    if isinstance(stmt, pyvex.stmt.IMark):  # once an IMARK is encountered..
        # release optimization query if detected
        if SCA._last_wrtmp_expr is not None:
            taint_info()
            # optimization()
            quantification()
            SCA._last_wrtmp_expr = None
            SCA._last_wrtmp_inst = None
        # print machine instruction
        (address, mnemonic, op_str) = SCA._last_inst
        l.info('\033[91m{}\033[0m'.format(machine_inst(address, mnemonic, op_str)))
    l.info('\033[0m{}'.format(stmt))


def analyze_reg_write(state: angr.SimState) -> None:
    expr = state.inspect.reg_write_expr
    inZ3 = claripy.backends.z3.convert(expr)
    offset = state.solver.eval(state.inspect.reg_write_offset)
    # offset = state.inspect.reg_write_offset
    register = state.arch.register_names[offset]
    # register = offset
    l.info('\033[94m{}{} == \033[33m{}\033[0m'.format(register, taint(expr), inZ3))


def quantification() -> None:
    # save the analysis query
    # SCA._py_query(SCA._last_wrtmp_inst[0], pickle.dumps(SCA._last_wrtmp_expr)) # TODO pickling removed

    (address, mnemonic, op_str, name) = SCA._last_wrtmp_inst
    inst = machine_inst(address, mnemonic, op_str)

    if SCA.model is pascal.RegisterAnalysis:
        SCA._register_expression[address] = pickle.dumps(SCA._last_wrtmp_expr)
        return

    if SCA.model is pascal.DynamicAnalysis:
        if SCA._last_wrtmp_expr.concrete is not True:
            l.error("Performing dynamic analysis but the expression is not concrete")
            return

        value = claripy.backends.z3.convert(SCA._last_wrtmp_expr).as_long()

        if address not in SCA._concrete_values:
            SCA._concrete_values[address] = [value]
        else:
            SCA._concrete_values[address].append(value)

        return

    # prepare the model function call
    expr = claripy.backends.z3.convert(SCA._last_wrtmp_expr)
    constraint = None
    if SCA.constraint is not None:
        constraint = claripy.backends.z3.convert(SCA.constraint)
    # call given model function according to signature
    (time, memory) = SCA.model(expr=expr,
                               name=name,
                               address=address,
                               inst=inst,
                               constraint=constraint,
                               flag=SCA._r2_flag,  # passing function flag
                               report=SCA._r2_model,  # passing function report
                               timeout=60)  # per quantification query


def optimization() -> None:
    # pascal.HammingWeight.z3.basic()
    solver = z3.Optimize()
    inZ3 = claripy.backends.z3.convert(SCA._last_wrtmp_expr)
    # save the analysis query
    SCA._py_query(SCA._last_wrtmp_inst[0], pickle.dumps(SCA._last_wrtmp_expr))
    # z3.FreshConst(z3.BitVecSort(inZ3.size()), '@' + str(hex(state.addr)))
    rd = SCA._last_wrtmp_inst[3]
    rd, rd_ = z3.BitVecs('{} {}\''.format(rd, rd), inZ3.size())
    # add symbolic path formula
    formula = rd == inZ3
    # print(formula)
    solver.add(formula)
    # add self-composition formula
    self_formula = rd_ == rel.self_compose(inZ3)[0]
    # print(self_formula)
    solver.add(self_formula)
    # hamming weight difference function
    hw_diff = bv.hw(rd) - bv.hw(rd_)
    # hamming weight difference must be greater than 0 (signed)
    solver.add(hw_diff >= 0)
    solver.add(rd != rd_)
    solver.push()
    # objective function: minimize hamming weight difference
    solver.minimize(hw_diff)
    # satisfiability checking
    # print(solver.sexpr())
    l.warning("--------------------------------------------")
    min_w = -1
    max_w = -1
    if bv.model(solver, taint=[rd.decl().name(), rd_.decl().name()]) == z3.sat:
        min_w = abs(solver.model().eval(hw_diff).as_long())
        l.warning("Minumum Hamming Weight Difference: {}".format(min_w))
    solver.pop()
    # if minmum hamming weight difference is equal to the bit-length of the input
    # then there is no need to run with maximization objective function.
    if min_w != inZ3.size():
        l.warning("")
        critical_value = None
        critical_value_ = None
        solver.push()
        # objective function: maximize hamming weight difference
        solver.maximize(hw_diff)
        if bv.model(solver, taint=[rd.decl().name(), rd_.decl().name()]) == z3.sat:
            max_w = abs(solver.model().eval(hw_diff).as_long())
            critical_value = solver.model().eval(rd).as_signed_long()
            critical_value_ = solver.model().eval(rd_).as_signed_long()
            l.warning("Maximum Hamming Weight Difference: {}".format(max_w))
        solver.pop()
        l.warning("--------------------------------------------")
        if min_w == 1 and max_w == 1:
            solver.push()
            discriminant = z3.Extract(0, 0, rd) ^ z3.Extract(0, 0, rd_) != 1  # REVIEW
            solver.add(discriminant)
            if bv.model(solver, taint=[rd.decl().name(), rd_.decl().name()]) == z3.unsat:
                SCA._r2_flag(SCA._last_wrtmp_inst[0], "vulnurable")
                l.error("\033[94mThe solution space collapses into two values at {}!\033[0m".format(
                    SCA._last_wrtmp_inst[0]))
            solver.pop()
        elif min_w == max_w and critical_value is not None and critical_value_ is not None:
            solver.push()
            solver.add(rd != critical_value)
            solver.add(rd_ != critical_value_)
            if bv.model(solver, taint=[rd.decl().name(), rd_.decl().name()]) == z3.unsat:
                l.error("\033[94mCritical value detected: {} in ({}, {}) at {}!\033[0m".format(
                    SCA._last_wrtmp_inst[3], critical_value, critical_value_, SCA._last_wrtmp_inst[0]))
                SCA._r2_flag(SCA._last_wrtmp_inst[0], "vulnurable")
            solver.pop()
    else:
        max_w = min_w
        SCA._r2_flag(SCA._last_wrtmp_inst[0], "vulnurable")
        l.error("--------------------------------------------")
        l.error("\033[94mThe solution space collapses into two values at {}!\033[0m".format(SCA._last_wrtmp_inst[0]))
        # l.error("--------------------------------------------")

    # save the analysis results
    SCA._r2_model(SCA._last_wrtmp_inst[0], "max ω = {:<2} ∘ min ω = {:<2}".format(max_w, min_w))


def taint_info() -> None:
    (address, mnemonic, op_str, _) = SCA._last_wrtmp_inst
    l.warning('\033[91m{}\033[0m'.format(machine_inst(address, mnemonic, op_str)))
    l.warning("\033[94mTainted {} instruction detected at {}!\033[0m".format(mnemonic, address))


def analyze_instr(state: angr.SimState) -> None:
    # to populate state.inspect.instruction
    vexblock: angr.Block = state.block()
    capstoneBlock: angr.block.DisassemblerBlock = vexblock.capstone
    l.debug('Is {} thumb? {}'.format(hex(state.inspect.instruction),
            state.project.arch.is_thumb(state.inspect.instruction)))
    n = vexblock.instruction_addrs.index(state.inspect.instruction)
    insn: angr.block.CapstoneInsn = capstoneBlock.insns[n]
    SCA._last_inst = (hex(address(state)), insn.mnemonic, insn.op_str)
    # SCA._last_inst = '\033[91m{}\033[0m'.format(machine_inst(hex(address(state)), insn.mnemonic, insn.op_str))


def analyze_snapshot(state: angr.SimState) -> None:
    l.info('{}'.format(state.regs))


def _tainted_read(state) -> bool:
    addr = state.inspect.mem_read_address
    return isAst(addr) and is_sensitive(addr)


# Call during a breakpoint callback on 'mem_write'
def _tainted_write(state) -> bool:
    addr = state.inspect.mem_write_address
    return isAst(addr) and is_sensitive(addr)


# Call during a breakpoint callback on 'exit' (i.e. conditional branch)
def _tainted_branch(state: angr.SimState) -> bool:  # TODO ???
    guard = state.inspect.exit_guard
    return isAst(guard) and is_sensitive(guard)


def isAst(x) -> bool:
    return isinstance(x, claripy.ast.Base)


def detected_memory_read(state: angr.SimState) -> None:
    l.info("Tainted Mem. Read:\n  Instruction Address {}\n  Read Address {}\n  Read Value {}".format(
        hex(state.addr), state.inspect.mem_read_address, state.inspect.mem_read_expr))


def detected_memory_write(state: angr.SimState) -> None:
    l.info("Tainted Mem. Write:\n  Instruction Address {}\n  Write Address {}\n  Write Value {}".format(
        hex(state.addr), state.inspect.mem_write_address, state.inspect.mem_write_expr))


def detected_memory_branch(state: angr.SimState) -> None:
    l.info("Tainted Branch:\n  Instruction Address {}\n  Branch Target {}\n  Guard {}".format(
        hex(state.addr), state.inspect.exit_target, state.inspect.exit_guard))


def getAddressOfSymbol(proj, symbolname):
    symb = proj.loader.find_symbol(symbolname)
    if symb is None:
        raise ValueError("symbol name {} not found".format(symbolname))
    return symb.rebased_addr


def goto_vulnurablities(base_addr: int, folder_name: str, file_name: str, func_name: str, vulnurebilities=[]):
    import subprocess
    SCA
    addr_mapping = {addr: '0x{0:0{1}x}'.format((abs(int(addr, 16) - base_addr)), 8) for addr in vulnurebilities}
    if len(addr_mapping) == 0:
        print("\nNo single-trace vulnurablity detected!")
        return
    else:
        print("\n\033[91mSingle-trace vulnurablities detected!\033[0m")
    wd = os.getcwd()
    os.chdir(os.path.join(wd, folder_name))
    # arm-none-eabi-addr2line -e /Users/ferhat/git/psca/benchmarks/01/csubq.o -f csubq -a 30 -p
    result = subprocess.run(["arm-none-eabi-addr2line", "-e", file_name, "-f", "-p", "-a", ] +
                            [str(hex(abs(int(addr, 16) - base_addr))) for addr in vulnurebilities],
                            capture_output=True, text=True).stdout.replace("/home", "/Users").replace((func_name + " "), "").replace("at ", "")
    for addr, mapped in addr_mapping.items():
        result = result.replace(mapped, addr)
    os.chdir(wd)
    print(result)
