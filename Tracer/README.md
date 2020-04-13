Capture syscalls performed by containers and automatically generate a Seccomp Profile.

# Usage
Start running the ``` containerExitCheck.py ```, this is reponsible for checking when a container exits. <br>
``` sudo python3 containerExitCheck.py ```

Start the tracing program, in the ``` dockerRun.sh ``` there is the recommended docker command. <br>
``` sudo ./dockerRun.sh ``` <br>
Once inside the container run the ``` tracer.py ``` program. <br>
``` python3 tracer.py ``` <br>

Wait until you the program outputs the word ``` Tracing ```. Now any newly spawned container will be traced, after the container exits you will find two files in the Capture directory, the files will have the same name as your container id had. 

Each line in the .cap file consists of: the time on which the syscall was called, the process that called the syscall, the namespace of the syscall and finally the syscall itself. 

The .json file consists of a Seccomp Profile whitelisting all the captured syscalls from the .cap file.

The logTracer.log file has information about what syscalls are being captured.
  
# Deploy a custom Seccomp Profile
``` sudo docker run --security-opt seccomp=./Path-to-profile <container> ```

# CI/CD Integration
In order to easilly mantain the Seccomp profiles you can integrate this solution with the CI/CD pipeline. Just make sure that you have the tracing solution running and when the unit test run they will do so in a container.

Having good unit tests that map all the funcionalities needed are crucial for a reliable profile.
