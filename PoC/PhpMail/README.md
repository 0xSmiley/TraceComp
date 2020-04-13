
Container: 
Run: sudo docker run -it -p 8080:80 vulnerables/cve-2016-10033

Exploit:
    Shell: ./exploit.sh localhost:8080
    Deface: ./deface.sh localhost:8080


Use custom seccomp profile and check that exploit does not work
Run: sudo docker run -it --security-opt seccomp=./phpMail.json -p 8080:80 vulnerables/cve-2016-10033
