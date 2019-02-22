from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DateTimeField
from wtforms.validators import DataRequired


class SearchForm(FlaskForm):
    src = StringField('src', validators=[DataRequired()])
    dst = StringField('dst', validators=[DataRequired()])
    srcport = StringField('srcport', validators=[DataRequired()])
    dstport = StringField('dstport', validators=[DataRequired()])
    start = DateTimeField('start', validators=[DataRequired()])
    end = DateTimeField('end', validators=[DataRequired()])
    submit = SubmitField('Search')
