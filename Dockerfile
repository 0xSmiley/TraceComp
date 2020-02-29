FROM ubuntu

RUN apt-get update \
    && apt-get install -y gnupg
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
RUN apt-get install lsb-core -y
RUN echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/iovisor.list
RUN apt-get update 
RUN apt-get install -y bcc-tools libbcc-examples linux-headers-$(uname -r) python3-bcc python3-pip
RUN pip3 install grpcio
RUN pip3 install grpcio-tools

