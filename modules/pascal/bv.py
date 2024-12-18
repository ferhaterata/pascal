import z3
import cvc5.pythonic as cvc5
from typing import Dict
import math

import logging
l = logging.getLogger(name='sca')


def project(goal: z3.Goal, term: z3.BitVecRef, bitmap={}) -> Dict:
    width = term.size()
    l = len(bitmap)
    for i in range(width):
        j = l + i
        bitmap[(term, j)] = z3.Bool('r['+str(j)+']')
        mask = z3.BitVecSort(width).cast(math.pow(2, i))
        goal.add(bitmap[(term, j)] == ((term & mask) == mask))
    return bitmap


def tactic() -> z3.Tactic:
    t = z3.Then('simplify', 'bit-blast', 'tseitin-cnf')
    return t


def hw(v: z3.BitVecRef) -> z3.BitVecRef:
    """expression to get hamming weight of a bit vector v"""
    """weight: the distance of v to the zero vector, which is equal to the number of 1's in it."""

    def extract(v, i):
        return z3.ZeroExt(math.floor(math.log2(v.size())), z3.Extract(i, i, v))

    expr = 0
    for i in range(v.size()):
        expr += extract(v, i)
    return expr


def hw_eq(v: z3.BitVecRef, count: int) -> z3.BoolRef:
    """
    https://stackoverflow.com/questions/43081929/k-out-of-n-constraint-in-z3py
    https://github.com/Z3Prover/z3/issues/960
    https://github.com/Z3Prover/z3/issues/755
    """
    return z3.PbEq([(z3.Extract(i, i, v) == 1, 1) for i in range(v.size())], count)


def hd(u: z3.BitVecRef, v: z3.BitVecRef) -> z3.BitVecRef:
    """expression to get the hamming distance of two bitvectors"""
    """distance: the number of places where u and v differ"""
    return hw(u ^ v)


def hd_eq(u: z3.BitVecRef, v: z3.BitVecRef, count: int) -> z3.BoolRef:
    h = u ^ v
    return z3.PbEq([(z3.Extract(i, i, h) == 1, 1) for i in range(u.size())], count)


def eval(model, term, name="r"):
    padding = len(name) + 1
    value = model.eval(term)
    return ('\033[91m{0:<{1}}\033[00m'.format(name, padding) + "= %s" % (format(value.as_long(), "0%db" % value.size())))


def model(solver: z3.Solver, taint=[], secret=[]):
    max_padding = 10

    def color(d):
        if (d.name() in taint):
            return '\033[91m{0:<{1}}\033[00m'.format(d.name(), max_padding)
        elif (d.name() in secret):
            return '\033[96m{0:<{1}}\033[00m'.format(d.name(), max_padding)
        else:
            return '\033[00m{0:<{1}}'.format(d.name(), max_padding)

    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        # print(model)
        l.warning("sat: traversing model...")
        max_padding = max([len(d.name()) for d in model.decls()]) + 1
        digits = max([len(str(model[d].as_signed_long())) for d in model.decls()])
        for d in model.decls():
            f = "= %" + str(digits) + "s = %s"
            # StateTracking.r2_model(hex(state.inspect.instructio), "min ω = {}".format(min_w))
            l.warning(color(d) + f %
                   (model[d].as_signed_long(), format(model[d].as_long(), "0%db" % model[d].size())))
        return z3.sat
    elif result == z3.unsat:
        l.error("unsat")
        return z3.unsat
    else:
        if solver.reason_unknown() == 'timeout':
            l.error(solver.reason_unknown())
        else:
            l.error("unknown")
        return z3.unknown


def print_model(model: Dict, taint=[], secret=[]):
    max_padding = 10
    model = {n: (v, int(v, base=2)) for n, v in model.items()}

    def color(name):
        if (name in taint):
            return '\033[91m{0:<{1}}\033[00m'.format(name, max_padding)
        elif (name in secret):
            return '\033[96m{0:<{1}}\033[00m'.format(name, max_padding)
        else:
            return '\033[00m{0:<{1}}'.format(name, max_padding)

    max_padding = max([len(name) for name in model.keys()]) + 1
    digits = max([len(str(v[1])) for v in model.values()])
    for name, (b, d) in model.items():
        f = "= %" + str(digits) + "s = %s"
        # StateTracking.r2_model(hex(state.inspect.instructio), "min ω = {}".format(min_w))
        l.warning(color(name) + f % (d, b))


# # Traversing statistics
# for k, v in s.statistics():
#     print("%s : %s" % (k, v))
def stat(solver: z3.Solver):
    print("statistics...")
    print("%6s" % "memory", "= %s" % solver.statistics().get_key_value('memory'))
    print("%6s" % "time", "= %f" % solver.statistics().get_key_value('time'))


def prove(f):
    s = z3.Solver()
    s.add(z3.Not(f))
    if s.check() == z3.unsat:
        print("proved")
    else:
        print("failed to prove")


def hw_cvc5(v):
    """expression to get hamming weight of a bit vector v"""
    """weight: the distance of v to the zero vector, which is equal to the number of 1's in it."""

    def extract(v, i):
        return cvc5.ZeroExt(math.floor(math.log2(v.size())), cvc5.Extract(i, i, v))

    expr = 0
    for i in range(v.size()):
        expr += extract(v, i)
    return expr


def to_cvc5(fml: z3.ExprRef) -> cvc5.ExprRef:

    def find_constants(fml: z3.ExprRef):
        symbols = {}

        def visitor(e, seen):
            if e in seen:
                return
            seen[e] = True
            yield e
            if z3.is_app(e):
                for ch in e.children():
                    for e in visitor(ch, seen):
                        yield e
                return

        for e in visitor(fml, seen={}):
            if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                # print("Variable", e)
                symbols[e.decl().name()] = cvc5.BitVec(e.decl().name(), e.size())

        return symbols


    def visit(e: z3.ExprRef):
        if z3.is_app(e):

            if z3.is_false(e):  # Z3_OP_TRUE:
                return True

            if z3.is_true(e):  # Z3_OP_FALSE:
                return False

            if z3.is_eq(e):
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left == right

            if z3.is_distinct(e):
                args = [visit(arg) for arg in e.children()]
                return cvc5.Distinct(args)

            if e.decl().kind() == z3.Z3_OP_ITE:
                a = visit(e.arg(0))
                b = visit(e.arg(1))
                c = visit(e.arg(2))
                return cvc5.If(a, b, c)

            if z3.is_and(e):  # z3.Z3_OP_AND
                args = [visit(arg) for arg in e.children()]
                return cvc5.And(args)

            if z3.is_or(e):  # z3.Z3_OP_OR:
                args = [visit(arg) for arg in e.children()]
                return cvc5.Or(args)

            #z3.Z3_OP_IFF = 263
            #z3.Z3_OP_XOR = 264

            if z3.is_not(e):  # z3.Z3_OP_NOT:
                arg = visit(e.arg(0))
                return cvc5.Not(arg)

            if z3.is_implies(e):  # z3.Z3_OP_IMPLIES:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.Implies(left, right)

            #z3.Z3_OP_OEQ = 267
            #z3.Z3_OP_ANUM = 512
            #z3.Z3_OP_AGNUM = 513
            #z3.Z3_OP_LE = 514
            #z3.Z3_OP_GE = 515
            #z3.Z3_OP_LT = 516
            #z3.Z3_OP_GT = 517
            #z3.Z3_OP_ADD = 518
            #z3.Z3_OP_SUB = 519
            #z3.Z3_OP_UMINUS = 520
            #z3.Z3_OP_MUL = 521
            #z3.Z3_OP_DIV = 522
            #z3.Z3_OP_IDIV = 523
            #z3.Z3_OP_REM = 524
            #z3.Z3_OP_MOD = 525

            if e.decl().kind() == z3.Z3_OP_BNEG:
                arg = visit(e.arg(0))
                return -arg

            if e.decl().kind() == z3.Z3_OP_BADD:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left + right

            if e.decl().kind() == z3.Z3_OP_BSUB:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left - right

            if e.decl().kind() == z3.Z3_OP_BMUL:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left * right

            if e.decl().kind() == z3.Z3_OP_BSDIV:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.SDiv(left, right)

            if e.decl().kind() == z3.Z3_OP_BUDIV:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.UDiv(left, right)

            if e.decl().kind() == z3.Z3_OP_BSREM:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.SRem(left, right)

            if e.decl().kind() == z3.Z3_OP_BUREM:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.URem(left, right)

            if e.decl().kind() == z3.Z3_OP_BSMOD:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.SMod(left, right)

            if e.decl().kind() == z3.Z3_OP_ULEQ:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.ULE(left, right)

            if e.decl().kind() == z3.Z3_OP_SLEQ:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left <= right

            if e.decl().kind() == z3.Z3_OP_UGEQ:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.UGE(left, right)

            if e.decl().kind() == z3.Z3_OP_SGEQ:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left >= right

            if e.decl().kind() == z3.Z3_OP_ULT:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.ULT(left, right)

            if e.decl().kind() == z3.Z3_OP_SLT:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left < right

            if e.decl().kind() == z3.Z3_OP_UGT:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.UGT(left, right)

            if e.decl().kind() == z3.Z3_OP_SGT:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left > right

            if e.decl().kind() == z3.Z3_OP_BAND:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left & right

            if e.decl().kind() == z3.Z3_OP_BOR:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left | right

            if e.decl().kind() == z3.Z3_OP_BNOT:
                arg = visit(e.arg(0))
                return ~arg

            if e.decl().kind() == z3.Z3_OP_BXOR:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left ^ right

            if e.decl().kind() == z3.Z3_OP_BXNOR:
                raise Exception("Unknown operator:z3.Z3_OP_BXNOR")

            if e.decl().kind() == z3.Z3_OP_BNAND:
                raise Exception("Unknown operator:z3.Z3_OP_BNAND")

            if e.decl().kind() == z3.Z3_OP_BNOR:
                raise Exception("Unknown operator:z3.Z3_OP_BNOR")

            if e.decl().kind() == z3.Z3_OP_BXNOR:
                raise Exception("Unknown operator:z3.Z3_OP_BXNOR")

            if e.decl().kind() == z3.Z3_OP_CONCAT:
                args = [visit(arg) for arg in e.children()]
                return cvc5.Concat(args)

            if e.decl().kind() == z3.Z3_OP_SIGN_EXT:
                n = e.params()[0]
                a = visit(e.arg(0))
                return cvc5.SignExt(n, a)

            if e.decl().kind() == z3.Z3_OP_ZERO_EXT:
                n = e.params()[0]
                a = visit(e.arg(0))
                return cvc5.ZeroExt(n, a)

            if e.decl().kind() == z3.Z3_OP_EXTRACT:
                a = visit(e.arg(0))
                high = e.params()[0]
                low = e.params()[1]
                return cvc5.Extract(high, low, a)

            #z3.Z3_OP_REPEAT = 1060
            #z3.Z3_OP_BREDOR = 1061
            #z3.Z3_OP_BREDAND = 1062
            #z3.Z3_OP_BCOMP = 1063

            if e.decl().kind() == z3.Z3_OP_BSHL:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left << right

            if e.decl().kind() == z3.Z3_OP_BLSHR:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.LShR(left, right)

            if e.decl().kind() == z3.Z3_OP_BASHR:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left >> right

            if e.decl().kind() == z3.Z3_OP_ROTATE_LEFT:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.RotateLeft(left, right)

            if e.decl().kind() == z3.Z3_OP_ROTATE_RIGHT:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return cvc5.RotateRight(left, right)

            if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                return symbols[e.decl().name()]

            if z3.is_bv_value(e):
                return cvc5.BitVecVal(e.as_long(), e.size())

            if z3.is_app(e):
                raise Exception("Unknown function: {}".format(str(e)))

            else:
                raise Exception("Unknown operator: {}".format(e.decl().kind()))

    symbols = find_constants(fml)
    return visit(fml)
