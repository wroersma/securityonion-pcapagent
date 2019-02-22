"""Get config information or set defaults."""
# coding=utf-8
import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class Config(object):
    """Set environment variables based on config."""

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    DATABASE_URL = os.environ.get('DATABASE_URL') or os.path.join(basedir, 'pcapmaster.db')
    #SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT')
    SERVER_NAME = os.environ.get('SERVER_NAME')
    ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL') or 'http://localhost:9200'
    LANGUAGES = ['en']
    BUNDLE_ERRORS = os.environ.get('BUNDLE_ERRORS') or True
    PCAP_PATH = os.environ.get('PCAP_PATH') or "."
