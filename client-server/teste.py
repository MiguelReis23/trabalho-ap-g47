import pytest 
from subprocess import Popen
from subprocess import PIPE

def testar(args, outputEsperado):
    proc = Popen(args, shell=True)
    return_code = proc.wait()
    output = proc.stdout.read().decode("utf-8")
    return return_code, output, output == outputEsperado

def test_invalid_args():
    