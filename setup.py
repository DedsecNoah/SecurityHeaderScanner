import os
packages=['termcolor','requests','webbrowser','time']
command = "pip install "
for i in packages:
    command += i
    os.system(command)
    command = "pip install "
