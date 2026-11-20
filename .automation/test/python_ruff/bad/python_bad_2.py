import subprocess


def foo():
    x = 1
    y = 2
    subprocess.call("echo hello", shell=True)
    return "\."
