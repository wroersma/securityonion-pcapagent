# securityonion-pcapagent

Requires Python 3.7  

PCAP Flow

## How to install and run from Python


    pip install -r requiremnets.txt
    export FLASK_APP=pcapagent.py.py
    export FLASK_DEBUG=1
    flask run

## How to run from docker

    docker build . -t securityonion-pcapagent
    sudo docker-compose up -d

###PCAP Agent

- Agent checks in every X seconds looking for jobs GET /getjobs


PCAP Server

Use ESID to pull PCAP
replace capme with bro
ESID need to be able to connect to elastic
Limit size of transcript
