import ipaddress
from app import app
from flask import jsonify
from flask import render_template
from flask import request
from app.forms import SearchForm

import logging, sys, json, os, glob, time


with open('config.json', 'r') as cfg:
    config = json.load(cfg)

# logging.basicConfig(filename=config["logFile"], level=logging.DEBUG)

STATUS = "AVAILABLE"

intervals = (
    ('weeks', 604800),  # 60 * 60 * 24 * 7
    ('days', 86400),    # 60 * 60 * 24
    ('hours', 3600),    # 60 * 60
    ('minutes', 60),
    ('seconds', 1),
    )

def check_avail(pcaptime):
    oldest = min(os.listdir(config["pcapPath"]), key=os.path.getctime)
    if oldest < pcaptime:
        return "BAD"
    else:
        return "GOOD"

def display_time(seconds, granularity=2):
    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append("{} {}".format(value, name))
    return ', '.join(result[:granularity])

def get_oldest_pcapfile():
    with app.app_context():
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

    return results

def validateip(ip):
    try:
        result = ipaddress.ip_address(ip)
        return result
    except ValueError:
        print 'Invalid IP Address'



@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/pcapstatus')
def get_status():
    return get_oldest_pcapfile()

@app.route('/search')
def search():
    form = SearchForm()
    return render_template('search.html', title='Search Pcap', form=form)

@app.route('/searchapi', methods=['GET','POST'])
def searchapi():
    if 'bpf' in request.args:
        bpf = str(request.args['bpf'])
    else:
        return "Error: This isn't the psychic friends network. I need a bpf"
    if 'start' in request.args:
        start = int(request.args['start'])
    else:
        return "Error: No start time provided. Please specify a start time."
    if 'end' in request.args:
        end = int(request.args['end'])
    else:
        return "Error: No end time specified. Plese specify an end time."






if __name__ == '__main__':
    app.run()
