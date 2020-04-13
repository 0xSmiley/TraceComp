There is always the possibility of a false negative occurring (a syscall that is not in the profile but should be). 

To deal with this we purpose a fuzzing solution in order to try and increase the coverage of needed syscalls. Fuzzing should only be an option when the unit case testing does not provide sufficient coverage on all of the functionalities that the container has.

# Usage

* Using the [tracing](https://github.com/0xSmiley/Runtime/blob/master/Tracer/README.md) solution 
* In the ``` conf.json ``` file you can set fuzzing containers. We provide a wrapper around docker so you can automatically deploy several fuzzing containers sequentially. 

```sudo python3 fuzzer.py ```
