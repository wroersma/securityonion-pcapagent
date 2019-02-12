import ipaddress
from app import app
from flask import jsonify
from flask import render_template
from flask import request
from app.forms import SearchForm
from flask_restful import reqparse
import sqlite3
from elasticsearch import Elasticsearch

import logging, sys, json, os, glob, time, datetime


with open('config.json', 'r') as cfg:
    config = json.load(cfg)

logging.basicConfig(filename=config["logFile"], level=logging.DEBUG)

# Create the database to store clients
db = sqlite3.connect(config["sensorDB"])
d = db.cursor()

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
        return False

def converttime(time):
    try:
        return blah
    except:
        return False

def addjob(sensor,stenoquery):
    db = sqlite3.connect(config["sensorDB"])
    d = db.cursor()

    # Create Sensor Table
    try:
        # Create Jobs Table
        d.execute('CREATE TABLE IF NOT EXISTS jobs  (jobid integer PRIMARY KEY AUTOINCREMENT, sensorid text, query text, jobstatus int)')
        db.commit()
        print("I added the table if it wasn't there.")
        d.execute('INSERT INTO jobs (sensorid, query, jobstatus) VALUES (?,?,0)', (sensor, stenoquery))
        db.commit()
        print(d.lastrowid)
        return str(d.lastrowid)

    except Exception as err:
        print("Something is wrong with the taterbase")
        print('Query Failed: %s\nError: %s' % (thequery, str(err)))


def getconn(connid):
    # Connect to Elastic and get information about the connection.
    esserver = config["esserver"]
    es = Elasticsearch(esserver)
    search = es.search(index=bro-conn*, doc-type="articles", body={"query": {"match": {"content": connid}}}) )
    hits = search['hits']['total']:
    if hits > 0:
        for result in search['hits']['hits']:
            src = result['source']
            dst = result['dest']
            srcport = result['sourceport']
            dstport = result['dstport']
            time = result['time']
            duration = result['duration']
            pcapafter = time - duration - 120
            pcapbefore = time + duration + 120
            sensor = result['sensor']
            stenoquery = "before %s and after %s and host %s and host %s and port %s and port %s" % (pcapbefore, pcapafter, src, dst, srcport, dstport)"
            return [sensor, stenoquery]
    else:
        print('No Results')

# See if I know about this sensor before I try and do something.
def checksensor(sensor):
    return sensor

@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/pcapstatus')
def get_status():
    return get_oldest_pcapfile()

@app.route('/search', methods=['GET','POST'])
def search():
    form = SearchForm()
    if form.validate_on_submit():
        src = string(request.args[src])
        return '''<h1>The Source is {}</h1>'''.format(src)

    return render_template('search.html', title='Search Pcap', form=form)

# Give it a conn id and let it do its thing.
@app.route('/searchbycid')

@app.route('/searchapi', methods=['GET','POST'])
def searchapi():
    parser = reqparse.RequestParser()
    parser.add_argument('src')
    parser.add_argument('dst')
    parser.add_argument('srcport')
    parser.add_argument('dstport')
    parser.add_argument('start')
    parser.add_argument('end')
    parser.add_argument('sensor')


    args = parser.parse_args()
    if validateip(args['src']) is False:
        return "%s is not a valid IP" % args['src']
    if validateip(args['dst']) is False:
        return "%s is not a valid IP" % args['dst']

    stenoquery = "before %s and after %s and host %s and host %s and port %s and port %s" % (args['end'], args['start'], args['src'], args['dst'], args['srcport'], args['dstport'])
    sensor = (args['sensor'])
    print('Adding the Job')
    result = addjob(sensor, stenoquery)
    return "Job ID %s has been added" % result

@app.route('/jobs', methods=['GET'])
def jobs():
    # Get all the jobs
    db = sqlite3.connect(config["sensorDB"])
    d = db.cursor()

    d.execute("SELECT * from jobs")
    jobsdata = d.fetchall()
    return render_template('jobs.html', jobsdata=jobsdata)

@app.route('/getjob')
def getjob():
    # Take a job from the queue
    db = sqlite3.connect(config["sensorDB"])
    d = db.cursor()

    parser = reqparse.RequestParser()
    parser.add_argument('sensor')
    args = parser.parse_args()
    sensor = args['sensor']
    d.execute('SELECT * from jobs WHERE jobstatus=0 and sensorid=? ORDER BY jobid ASC', (sensor,))
    job = d.fetchone()
    return jsonify(job)

@app.route('/updatejob')
def updatejob():
    # Update the status
    db = sqlite3.connect(config["sensorDB"])
    d = db.cursor()
    parser = reqparse.RequestParser()
    parser.add_argument('jobid')
    parser.add_argument('jobstatus')
    args = parser.parse_args()
    jobid = args['jobid']
    jobstatus = args['jobstatus']

    d.execute('UPDATE jobs SET jobstatus=? WHERE jobid=?', (jobstatus,jobid))

# Sensor registration
@app.route('/sensor', methods=['POST'])
def sensor():
    db = sqlite3.connect(config["sensorDB"])
    d = db.cursor()

    parser = reqparse.RequestParser()
    parser.add_argument('sensor')
    parser.add_argument('oldestpcap')
    parser.add_argument('lastcheckin')
    args = parser.parse_args()

    # Create Sensor Table if it is not there
    try:
        d.execute('CREATE TABLE IF NOT EXISTS sensors (id text PRIMARY KEY, oldestpcap int, lastcheckin int')
        d.execute(f"INSERT INT sensors (id, oldestpcap, lastcheckin') VALUES ({args['sensor']}, {args['oldestpcap']}, {args['lastcheckin']})")
    except:
        print('Something is broken')




# Have something to handle the delivery of the pcap
@app.route('/uploadjob', methods=['POST'])
def uploadjob():
    return 'yo'

if __name__ == '__main__':
    app.run()
