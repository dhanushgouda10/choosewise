import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:cherry2408@localhost:3306/user_auth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'your_mail_server.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@example.com'

mail = Mail(app)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

# ✅ Read CSV files instead
amazon_df = pd.read_csv("merged_amazon.csv")
flipkart_df = pd.read_csv("merged_flipkart.csv")

# Modify these column names as per your CSV headers
def normalize_amazon_image(url: str):
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url:
        return None
    # Remove the /W/<token>/images/ prefix Amazon sometimes injects which can block hotlinking
    match = re.match(r"(https://m\\.media-amazon\\.com/images/)(?:W/[^/]+/images/)(.+)", url)
    if match:
        return match.group(1) + match.group(2)
    return url


amazon_data = pd.DataFrame({
    'platform': 'Amazon',
    'link': amazon_df['single-href'],
    'title': amazon_df['title'],
    'price': amazon_df['price'],
    'image': amazon_df['image-src'].apply(normalize_amazon_image),
    'rating': amazon_df['rating'],
})

flipkart_data = pd.DataFrame({
    'platform': 'Flipkart',
    'link': flipkart_df['single-href'],
    'title': flipkart_df['title'],
    'price': flipkart_df['price'],
    'image': flipkart_df['image-src'],
    'rating': flipkart_df['rating'],
})

all_products = pd.concat([amazon_data, flipkart_data], ignore_index=True)
# Precompute a normalized title for resilient searching
all_products['title'] = all_products['title'].fillna('')
all_products['normalized_title'] = (
    all_products['title']
    .str.lower()
    .str.replace(r"[^a-z0-9]+", "", regex=True)
)

@app.before_request
def create_tables():
    db.create_all()

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/products', methods=['GET', 'POST'])
def products():
    # Accept query from either GET (?q=...) or POST (q or query)
    query = request.values.get('q', '')
    if not query:
        query = request.values.get('query', '')
    amazon_results = []
    flipkart_results = []

    if query:
        q_lower = query.strip().lower()
        tokens = re.findall(r"[a-z0-9]+", q_lower)
        q_norm = re.sub(r"[^a-z0-9]+", "", q_lower)

        # Strategy 1: All tokens must appear (case-insensitive) in original title
        if tokens:
            mask_all = True
            for t in tokens:
                mask_all = mask_all & all_products['title'].str.contains(re.escape(t), case=False, na=False)
        else:
            mask_all = all_products['title'].str.contains(re.escape(q_lower), case=False, na=False)

        filtered = all_products[mask_all]

        # Strategy 2: If none, try any token in original title
        if filtered.empty and tokens:
            mask_any = False
            for t in tokens:
                mask_any = mask_any | all_products['title'].str.contains(re.escape(t), case=False, na=False)
            filtered = all_products[mask_any]

        # Strategy 3: If still none, try normalized contains on normalized title
        if filtered.empty and q_norm:
            mask_norm = all_products['normalized_title'].str.contains(re.escape(q_norm), na=False)
            filtered = all_products[mask_norm]

        amazon_results = filtered[filtered['platform'] == 'Amazon'].to_dict(orient='records')
        flipkart_results = filtered[filtered['platform'] == 'Flipkart'].to_dict(orient='records')

    return render_template('results.html', 
                         amazon_products=amazon_results, 
                         flipkart_products=flipkart_results, 
                         query=query)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists!')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        # Send confirmation email
        msg = Message('Registration Confirmation', recipients=[email])
        msg.body = f"Hello {username},\n\nThank you for registering with Choose Wise!\n\nBest regards,\nThe Choose Wise Team"
        try:
            mail.send(msg)
            flash('Registration successful! A confirmation email has been sent. Please log in.', 'success')
        except Exception as e:
            flash(f'Registration successful, but failed to send confirmation email: {e}', 'error')

        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if not username_or_email or not password:
            flash('Username/email and password are required.', 'error')
            return render_template('loginvercel.html')
        
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('products'))
        else:
            flash('Invalid username/email or password!', 'error')
            return render_template('loginvercel.html')
    return render_template('loginvercel.html')


@app.route('/loginvercel', methods=['GET'])
def loginvercel():
    return render_template('loginvercel.html')
    
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('signup.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html')

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists!', 'error')
            return render_template('signup.html')

        try:
            hashed_pw = generate_password_hash(password)
            new_user = User(username=username, email=email, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('loginvercel'))
        except Exception as e:
            flash(f'Unable to create account: {str(e)}', 'error')
            return render_template('signup.html')

    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)
