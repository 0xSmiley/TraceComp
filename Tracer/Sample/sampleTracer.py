
import os

stream=os.popen('docker inspect -f {{.State.Running}} cf0fa9500b67')
a = stream.read().strip()
if a=="true" :
  print("Running ",a)
else:
  print("Not Running ",a)

stream = os.popen('echo Returned output')
output = stream.read()
  

