import sys
import logging
import json
import requests

with open('config.json', 'r') as cfg:
    config = json.load(cfg)

# Setup logging

logging.basicConfig(filename=config["logFile"], level=config["logLevel"])

# This tells the master the oldest PCAP the sensor has every 5 minutes or so
def updatestatus():


def getjobs():
    master = config["master"]
    sensorname = config["sensorname"]
    jobs = requests.get('%s/getjobs?sensor=%s') (master, sensorname)
    # Need to parse the JSON output here to get stenoquery
    jobs.json()
    updatejob = requests.post('%s/updatejob?jobid=%s&jobstatus=1')(master, jobid)
    dojob(stenoquery, jobid)

def dojob(stenoquery, jobid):
    # Run the steno job
    getpcap = stenoread 'stenoquery' -w /nsm/pcapout/%s.pcap (jobid)
    #Wait till it is done
    uploadpcap = requests.post('%s/uploadpcap?jobid=%s')

