import claripy

class Sensitive(claripy.Annotation):
    """
    Annotation for doing taint-tracking in angr.
    """

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

    def relocate(self, src, dst):
        srcAnnotations = list(src.annotations)
        if len(srcAnnotations) == 0:
            return None
        elif len(srcAnnotations) == 1:
            return srcAnnotations[0]
        else:
            return srcAnnotations[0] # TODO: this is a hack
            # raise ValueError("more than one annotation: {}".format(srcAnnotations))

def is_sensitive(ast) -> bool:
    return _is_immediately_tainted(ast) or any(_is_immediately_tainted(v) for v in ast.leaf_asts())


def _is_immediately_tainted(ast) -> bool:
    return any(isinstance(a, Sensitive) for a in ast.annotations)
