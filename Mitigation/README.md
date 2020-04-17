Learn what syscalls are used by an exploit and removed them from your current Seccomp profile.

# Requirements
Working proof of concept.

# Usage
* Using the [tracing](https://github.com/0xSmiley/Runtime/blob/master/Tracer/README.md) solution 
  * Generate a Seccomp profile for the exploit proof of concept
  * Generate a second Seccomp profile mapping the required features for the application 
* Using the ``` mit.py ``` see what syscalls are in the first profile that are not in the second.

# Example


* Using the flag -poc supply the path the first Seccomp profile;
* Using the flag -useC supply the path the second Seccomp profile;


``` 
python3 mit.py -poc poc.json -useC usecase.json 

Vulnerable syscalls:
	statfs
	vfork
	select 
```

If you have a vulnerable Seccomp profile you can supply it to the program and the vulnerable syscalls will be removed. Even though this might mitigate the vulnerability should be a temporary fix and done only as a last resource since it might break some funcionality in the application.
* Using the flag -all supply the path your current Seccomp profile.
* A new profile will be generated without the vulnerable syscalls.

``` 
python3 mit.py -poc poc.json -useC usecase.json -all fuzzed.json
```
