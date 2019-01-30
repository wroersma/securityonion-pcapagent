from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DateTimeField
from wtforms.validators import DataRequired

class SearchForm(FlaskForm):
    bpf = StringField('bpf', validators=[DataRequired()])
    start = DateTimeField('start', validators=[DataRequired()])
    end = DateTimeField('end', validators=[DataRequired()])
    submit = SubmitField('Search')