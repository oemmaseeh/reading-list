from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from forms import RegistrationForm
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://wnkwkdcd:23b2dCs6bBz3lMXQoLvpbN5E9uClJBKT@bubble.db.elephantsql.com/wnkwkdcd'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '1564'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
csrf = CSRFProtect(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('books', lazy=True))

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/books')
def book_list():

    return render_template('book_list.html', books=books)

@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if request.method == 'POST':

        return redirect(url_for('book_list'))
    return render_template('add_book.html')

@app.route('/delete_book/<int:book_id>', methods=['POST'])
def delete_book(book_id):

    return redirect(url_for('book_list'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('book_list'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='Username already exists')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)