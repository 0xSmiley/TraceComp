FROM bwits/docker-git-alpine

WORKDIR /tmp/
RUN git clone https://github.com/maurosoria/dirsearch && rm -rf /tmp/dirsearch/.git

FROM python:3-alpinec

WORKDIR /root/
COPY --from=0 /tmp/dirsearch dirsearch

ENTRYPOINT ["/root/dirsearch/dirsearch.py"]
WORKDIR /root/dirsearch/

CMD [ "-h"]