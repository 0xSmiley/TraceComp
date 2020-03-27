FROM python:3.7
WORKDIR /app/
RUN apt-get update -y \
    && apt-get install -y \
    python3 \
    python3-pip
RUN pip3 install argparse

CMD python3 client.py
