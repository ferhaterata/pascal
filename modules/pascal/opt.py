import os
import platform
import subprocess
import re

import logging
l = logging.getLogger(name='sca')


def optimathsat(sexpr, timeout=1200):
    """
    https://stackoverflow.com/questions/55363925/can-i-get-a-solution-using-timeout-when-using-optimize-minimize
    https://stackoverflow.com/questions/60841582/timeout-for-z3-optimize
    https://stackoverflow.com/questions/48437608/finding-suboptimal-solution-best-solution-so-far-with-z3-command-line-tool-and/
    """
    template = f'''
; ./optimathsat -optimization=true -printer.bv_number_format=0 
;               -printer.model_as_formula=true ../../../opt.smt2
(set-option :produce-models true)
(set-logic QF_BV)
(set-option :timeout {float(timeout)})

(set-option :config opt.soft_timeout=true) ;mathsat5
;(set-option :config opt.theory.bv.engine=obvwa) ;mathsat5

(set-option :parallel.enable true);z3
(set-option :pp.bv-literals true) ;z3
(set-option :verbose 2)           ;z3

{sexpr}
(push 1)
(minimize w)
(check-sat)
(get-objectives)
(echo "mininimum")
(get-model)
(pop 1)

(push 1)
(maximize w)
(check-sat)
(get-objectives)
(echo "maximum")
(get-model)
(pop 1)

(get-info :all-statistics)
(exit)
'''
    # if debug:
    # print(template)
    file = open("opt.smt2", "w")
    file.write(template)
    file.close()
    wd = os.getcwd()
    if platform.system() == 'Linux':
        os.chdir(wd + '/omt/optimathsat-1.7.3-linux-64-bit/bin/')
    elif platform.system() == 'Darwin':
        os.chdir(wd + '/omt/optimathsat-1.7.3-macos-64-bit/bin/')
    else:
        raise Exception('Unsupported platform')
    out = subprocess.run(['./optimathsat', '-optimization=true',
                          '-printer.bv_number_format=1', '-printer.model_as_formula=true',
                          '../../../opt.smt2'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    os.chdir(wd)
    l.debug(out)

    min_model, max_model, time, memory = {}, {}, 0.0, 0.0

    models = re.findall(r'^  \(= (.*?)\)', out, re.M)
    for m in models:
        k, v = m.split(' ')
        k = k.replace('|', '', 2)
        v = v[2:]
        if min_model.get(k) is None:
            min_model[k] = v
        else:
            max_model[k] = v

    regex = re.match(r'^.*?\n  :time-seconds ((0|[1-9]\d*)(\.\d+)?)', out, re.DOTALL)
    if regex:
        time = float(regex.group(1))

    regex = re.match(r'^.*?\n  :memory-mb ((0|[1-9]\d*)(\.\d+)?)', out, re.DOTALL)
    if regex:
        memory = float(regex.group(1))

    return (min_model, max_model, time, memory)
