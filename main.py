import os

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo, DataRequired

app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '123456789'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@login_manager.user_loader
def load_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        return user

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    surname = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    
    def __repr__(self):
        return f"User('{self.name}', '{self.surname}', '{self.email}')"
  


class Pages(db.Model):
    __tablename__='pages'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def __repr__(self):
        return f"Pages('{self.title}', '{self.date_posted}')"

    
class RegistrationForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(min=2, max=30)], render_kw={"placeholder": "Name"})
    surname = StringField(validators=[InputRequired(), Length(min=2, max=30)], render_kw={"placeholder": "Surname"})
    email = StringField(validators=[InputRequired(), Email(), Length(max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=30)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), EqualTo('password', message='Passwords must match')], render_kw={"placeholder": "Confirm Password"}) 
    submit = SubmitField('Sign Up')

    def validate_name(self, name):
        if not name.data.isalpha():
            raise ValidationError('Name can only contain letters.')

    def validate_surname(self, surname):
        if not surname.data.isalpha():
            raise ValidationError('Surname can only contain letters.')
        
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email address already taken.')
        
    def save_user(self):
        hashed_password = generate_password_hash(self.password.data)
        user = User(name=self.name.data, surname=self.surname.data, email=self.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        return user


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')
    
class ProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    surname = StringField('Surname', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    profile_picture = FileField('Update Profile Picture', validators=[FileAllowed(['png', 'jpg', 'jpeg', 'gif'])])
    submit = SubmitField('Save Changes')

    def update_profile(self, user):
        user.name = self.name.data
        user.surname = self.surname.data
        user.email = self.email.data

        if self.profile_picture.data:

            filename = secure_filename(self.profile_picture.data.filename)
            self.profile_picture.data.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            user.profile_picture_path = os.path.join(UPLOAD_FOLDER, filename)

        db.session.commit()



class UpdateProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    surname = StringField('Surname', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    profile_picture = FileField('Profile Picture')
    submit = SubmitField('Save Changes')

class UploadForm(FlaskForm):
    file = FileField('Profile Picture', validators=[DataRequired(), FileAllowed(['jpg', 'jpeg', 'png'])])

######################################route#################################

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('You have been logged in!', 'success')
                return redirect(url_for('profile'))
        if user is None:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', title='Sign In', form=form)



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(name=form.name.data, surname=form.surname.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)  
        flash('Your account has been created!', 'success')
        return redirect(url_for('upload_profile_picture'))

    return render_template('register.html', title='Register', form=form)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user  # assuming you are using Flask-Login
    form = ProfileForm()
    if form.validate_on_submit():
        if form.profile_picture.data:
            # Save profile picture
            profile_pic = form.profile_picture.data
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # Update user's profile picture
            current_user.profile_picture = filename
            db.session.commit()

        # Update user's other profile information
        current_user.name = form.name.data
        current_user.surname = form.surname.data
        current_user.email = form.email.data
        db.session.commit()

        return redirect(url_for('dashboard'))

    elif request.method == 'GET':
        form.name.data = current_user.name
        form.surname.data = current_user.surname
        form.email.data = current_user.email

    return render_template('profile.html', user=current_user, display_image=display_image)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')

@app.route('/upload_profile_picture', methods=['GET', 'POST'])
@login_required
def upload_profile_picture():
    form = UploadForm()
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No PHOTO part')
            return redirect(request.url)
        file = request.files['photo']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.profile_picture = filename
            db.session.commit()
            flash('Profile picture updated successfully.')
            return redirect(url_for('profile'))
        else:
            flash('Invalid file type. Allowed types are png, jpg, jpeg, gif.')
            return redirect(request.url)
    return render_template('upload_profile_picture.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/display/<filename>')
def display_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.surname = form.surname.data
        current_user.email = form.email.data
        if form.profile_picture.data:
            picture_file = save_picture(form.profile_picture.data)
            current_user.image_file = picture_file
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.name.data = current_user.name
        form.surname.data = current_user.surname
        form.email.data = current_user.email
    return render_template('update_profile.html', title='Update Profile', form=form)



@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash('You have been logged out', 'success')
    return redirect(url_for('login'))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    








