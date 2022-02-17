import os
packages=['termcolor','requests','webbrowser','time']
ip = "192.168.0.1"
command = "pip install "
for i in packages:
    command += i
    os.system(command)
    command = "pip install "
