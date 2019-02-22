"""The Security Onion PCAP Agent FLASK APP."""
# coding=utf-8
from app import app, db
from app import routes


@app.shell_context_processor
def make_shell_context():
    """Main flask app running service for production use."""
    return {'db': db}
