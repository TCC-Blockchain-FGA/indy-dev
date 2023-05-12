FROM ubuntu:18.04

RUN useradd -G root -ms /bin/bash indy

RUN apt update -y && apt install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get install -y python3.7

# Install environment
RUN apt-get update -y && apt-get install -y \
    wget \
    python3.7 \
    python-setuptools \
    apt-transport-https \
    ca-certificates \
    software-properties-common

RUN apt install -y python3-pip

RUN pip3 install -U Flask

WORKDIR /home/indy

RUN pip3 install -U \
    pip \
    setuptools \
    python3-indy==1.6.2-dev-720 \
    asyncio

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys CE7709D068DB5E88
RUN add-apt-repository "deb https://repo.sovrin.org/sdk/deb bionic stable"
RUN apt-get update
RUN apt-get install -y libindy
RUN apt-get install -y indy-cli

# If you're working on your own project in a separate dir structure, change this to set the proper entry point for python.
ENV PYTHONPATH="/home/indy/python"

EXPOSE 8080
