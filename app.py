from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
global a
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///community_service.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
ki=[]
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from flask_login import UserMixin

class Volunteer(UserMixin, db.Model):     
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(1000), nullable=False, unique=True)
    password = db.Column(db.String(1000), nullable=False)
    email = db.Column(db.String(1000), nullable=False)

class Company(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

class Opportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    company = db.relationship('Company', backref='opportunities')

from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, EqualTo

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=100)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=100)])
    role = SelectField('Login as', choices=[('volunteer', 'Volunteer'), ('company', 'Company')])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=100)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=100), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Sign Up')

class OpportunityForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(max=500)])
    category = SelectField('Category', choices=[('environment', 'Environment'), ('education', 'Education'), ('health', 'Health')])
    submit = SubmitField('Create Opportunity')


@login_manager.user_loader
def load_user(user_id):
    if 'role' in session:
        if session['role'] == 'volunteer':
            return Volunteer.query.get(int(user_id))
        elif session['role'] == 'company':
            return Company.query.get(int(user_id))
    return None
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = form.role.data

        if role == 'volunteer':
            volunteer = Volunteer.query.filter_by(username=username).first()
            if volunteer and bcrypt.check_password_hash(volunteer.password, password):
                ki.append(username);ki.append(role)
                session['role'] = 'volunteer'
                login_user(volunteer)
                return redirect(url_for('home'))
        elif role == 'company':
            company = Company.query.filter_by(company_name=username).first()
            if company and bcrypt.check_password_hash(company.password, password):
                ki.append(username);ki.append(role)
                session['role'] = 'volunteer'
                session['role'] = 'company'
                login_user(company)
                a=username
                return redirect(url_for('company_home'))
        flash('Invalid credentials, please try again')
    
    return render_template('login.html', form=form)

@app.route('/volunterr_signup', methods=['GET', 'POST'])
def volunteer_signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        try:
            volunteer = Volunteer(username=form.username.data, password=hashed_password, email=form.email.data)
            db.session.add(volunteer)
            db.session.commit()
            flash('Volunteer account created! You can now login.')
            return redirect(url_for('login'))
        except:
            flash('account aldread exists redirected to login')
            return redirect(url_for('login'))
    return render_template('volunteer_signup.html', form=form)

@app.route('/company_signup', methods=['GET', 'POST'])
def company_signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        try:
            company = Company(company_name=form.username.data, password=hashed_password)
            db.session.add(company)
            db.session.commit()
            flash('Company account created! You can now login.')
            return redirect(url_for('login'))
        except:
            flash('account aldread exists redirected to login')

            return redirect(url_for('login'))

    return render_template('company_signup.html', form=form)

@app.route('/home')
@login_required
def home():
    #hg=Volunteer.query.filter_by(username=ki[0])
    opportunities = Opportunity.query.all()
    return render_template('home.html', opportunities=opportunities,profile=ki)

@app.route('/company_home', methods=['GET', 'POST'])
@login_required
def company_home():
    form = OpportunityForm()
    if form.validate_on_submit():
        opportunity = Opportunity(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            company_id=current_user.id
        )
        db.session.add(opportunity)
        db.session.commit()
        flash('Opportunity created successfully!')
        return redirect(url_for('company_home'))
    return render_template('company_home.html', form=form,profile=ki)

@app.route('/logout')
@login_required
def logout():

    logout_user()
    session.pop('role', None)
    try:
        del ki[0]
        del ki[1]
    except:
        pass
    return redirect(url_for('index'))
'''rohan=int(input("delete what "))
rew=Company.query.get(rohan)
session.delete(int(rew))
session.commit()'''
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
