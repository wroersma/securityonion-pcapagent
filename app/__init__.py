import logging
import os
import sqlite3
from logging.handlers import RotatingFileHandler
from flask import Flask
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

if app.config['LOG_TO_STDOUT']:
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    app.logger.addHandler(stream_handler)
else:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/pcapserver.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s '
                                                '[in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
db = sqlite3.connect(app.config['DATABASE_URL'])
d = db.cursor()

