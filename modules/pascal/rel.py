from typing import Dict, Tuple
from z3 import *


def test():
    symbols = {}

    def visit(e: ExprRef):
        # print(e.decl().kind())
        if is_app(e):
            if e.decl().kind() == Z3_OP_BADD:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left + right

            elif e.decl().kind() == Z3_OP_SGT:
                left = visit(e.arg(0))
                right = visit(e.arg(1))
                return left > right

            elif is_const(e) and e.decl().kind() == Z3_OP_UNINTERPRETED:
                return symbols[e]

            else:
                return e

    x, y = BitVecs('x y', 8)
    fml = x + x + y > 2

    print(fml)
    find_constants(fml)
    print(symbols)
    fml_ = visit(fml)
    print(fml_)

    # Converting into list of tuple
    # list = [(k, v) for k, v in dict.items()]

    fml__ = substitute(fml, list(symbols.items()))
    print(fml_)

# test()

def find_constants(fml: ExprRef):
    symbols = {}

    def visitor(e, seen):
        if e in seen:
            return
        seen[e] = True
        yield e
        if is_app(e):
            for ch in e.children():
                for e in visitor(ch, seen):
                    yield e
            return

    for e in visitor(fml, seen={}):
        if is_const(e) and e.decl().kind() == Z3_OP_UNINTERPRETED:
            # print("Variable", e)
            symbols[e] = FreshConst(BitVecSort(e.size()), e.decl().name())

    return symbols


def self_compose(fml: ExprRef) -> Tuple[ExprRef, Dict[ExprRef, ExprRef]]:
    symbols = find_constants(fml)
    return (substitute(fml, list(symbols.items())), symbols)


# def substitute(fml: ExprRef, public_vars: list) -> ExprRef:
#     """
#     Substitute all public variables with fresh constants
#     :param fml:
#     :param public_vars:
#     :return:
#     """
#     if not public_vars:
#         return fml
