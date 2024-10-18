from flask import render_template,request,redirect,url_for,flash,session
import flask_login
from flask_login import login_user,logout_user,current_user,login_required
from app import models,forms
from app.models import User
from app.forms import RegistrationForm,LoginForm,EditProfileForm
from app import app,db,bcrypt

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.','success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            session['user_id'] = user.id
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check your email and password','danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/edit_profile', methods=['GET','POST'])
def edit_profile():
    user_id = session['user_id']
    user = User.query.get_or_404(user_id)
    form = EditProfileForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.username = form.username.data
        user.email = form.email.data
        user.password = hashed_password
        db.session.commit()
        flash('Your account has been modified! ','success')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email

    return render_template('edit_profile.html', form=form)

