import subprocess
import os
a=subprocess.Popen(["python","registry.py","WinXPSP1x64","./samples/stuxnet.vmem"],shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
b=a.communicate()
print b
