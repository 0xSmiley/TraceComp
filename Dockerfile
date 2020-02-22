FROM ubuntu:latest

COPY /lib/modules /lib/modules:ro 
COPY /usr/src /usr/src:ro
COPY /var/run/docker.sock /var/run/docker.sock
COPY /etc/localtime /etc/localtime:ro

RUN apt update \
    apt-get install python3.7 -y \
    apt install python3-bpfcc -y 

WORKDIR /tracer
CMD [ "python3", "tracer.py" ]