

# [Tracer](https://github.com/0xSmiley/Runtime/blob/master/Tracer/README.md) <br/>
Solution to capture all the syscalls generated by newly spawned containers and generate a Seccomp Profile whitelisting those captured syscalls.

# [Mitigation](https://github.com/0xSmiley/Runtime/blob/master/Mitigation/README.md) <br/>
  If you have a working proof of concept you will be able to detect the syscalls that the exploit uses.
  
# [Fuzzer](https://github.com/0xSmiley/Runtime/blob/master/Fuzzer/README.md) <br/>
  Used to fuzz containers in order to increse the syscalls coverage. 


# Requirements:  <br/>
* [Docker](https://docs.docker.com/get-docker/)
* Python3 
* Pip3 
  * Docker 
  * Grpcio 
  * Grpcio-tools 
  * Argparse <br/>
  
pip3 install -r requirements


# PoCs:  <br/>

[PhpMail](https://github.com/0xSmiley/Runtime/blob/master/PoC/PhpMail/README.md). <br/>
[Nginx](https://github.com/0xSmiley/Runtime/blob/master/PoC/Nginx/README.md). <br/>
[Apache](https://github.com/0xSmiley/Runtime/blob/master/PoC/ApacheTomcat/README.md). <br/>
