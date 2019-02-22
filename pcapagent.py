import os
import logging
import json
import requests
from datetime import time
from flask import jsonify

with open('agentconfig.json', 'r') as cfg:
    config = json.load(cfg)

# Setup logging

logging.basicConfig(filename=config["logFile"], level=config["logLevel"])

# This tells the master the oldest PCAP the sensor has every 5 minutes or so
def updatestatus():
    now = time.time()
    oldest = min(os.listdir(config["pcapPath"]), key=os.path.getctime)
    filename = os.path.abspath(oldest)
    filectime = os.path.getatime(filename)
    age = (now - filectime)
    agehuman = display_time(age)
    results = jsonify(filename=filename,
                              createtime=filectime,
                              status=STATUS,
                              history=agehuman)


def getjobs():
    master = config["master"]
    sensorname = config["sensorname"]
    jobs = requests.get('%s/getjobs?sensor=%s') (master, sensorname)
    # Need to parse the JSON output here to get stenoquery
    jobs.json()
    updatejob = requests.post('%s/updatejob?jobid=%s&jobstatus=1')(master, jobid)
    updatejob()
    #dojob(stenoquery, jobid)

def dojob(stenoquery, jobid):
    # Run the steno job
    getpcap = stenoread 'stenoquery' -w /nsm/pcapout/%s.pcap (jobid)
    #Wait till it is done
    uploadpcap = requests.post('%s/uploadpcap?jobid=%s')

