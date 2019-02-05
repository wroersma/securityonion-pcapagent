from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config['BUNDLE_ERRORS'] = True
from app import routes