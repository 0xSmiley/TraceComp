FROM ubuntu
WORKDIR /gen/
RUN apt-get update -y \
    && apt-get install -y \
    gcc \
    make \
    git \
    wget 
RUN git clone https://gitlab.com/akihe/radamsa.git \
    && cd radamsa \
    && make \
    && make install

ENTRYPOINT ["radamsa"]
CMD [ "-h"]
