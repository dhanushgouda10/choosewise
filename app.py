import os
import re
from typing import Dict, Optional

import pandas as pd
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from supabase import Client, create_client
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_ANON_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError(
        "Missing Supabase configuration. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your .env file."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_secret")

# Flask-Mail configuration (kept for future use; configure via env if needed)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'your_mail_server.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = bool(int(os.environ.get('MAIL_USE_TLS', 1)))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your_email@example.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your_email_password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'your_email@example.com')

mail = Mail(app)

PRODUCT_COLUMNS = ['platform', 'link', 'title', 'price', 'image', 'rating']


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


def load_products_dataframe() -> pd.DataFrame:
    """
    Fetch product catalog from Supabase and normalize it for search.
    Expecting a `products` table with columns that map to PRODUCT_COLUMNS.
    """
    try:
        response = supabase.table("products").select(",".join(PRODUCT_COLUMNS)).execute()
    except Exception as exc:
        app.logger.error("Failed to fetch products from Supabase: %s", exc)
        return pd.DataFrame(columns=PRODUCT_COLUMNS + ['normalized_title'])

    records = response.data or []
    df = pd.DataFrame(records)
    if df.empty:
        return pd.DataFrame(columns=PRODUCT_COLUMNS + ['normalized_title'])

    # Normalize columns to avoid KeyErrors
    for column in PRODUCT_COLUMNS:
        if column not in df.columns:
            df[column] = None

    df['title'] = df['title'].fillna('')
    df['normalized_title'] = (
        df['title']
        .str.lower()
        .str.replace(r"[^a-z0-9]+", "", regex=True)
    )

    # Optional normalization specific to Amazon images
    if 'image' in df.columns:
        df.loc[df['platform'].str.lower() == 'amazon', 'image'] = (
            df.loc[df['platform'].str.lower() == 'amazon', 'image']
            .apply(normalize_amazon_image)
        )

    return df


def get_user_by_username(username: str) -> Optional[Dict]:
    response = supabase.table("users").select("*").eq("username", username).limit(1).execute()
    data = response.data or []
    return data[0] if data else None


def get_user_by_email(email: str) -> Optional[Dict]:
    response = supabase.table("users").select("*").eq("email", email).limit(1).execute()
    data = response.data or []
    return data[0] if data else None


def get_user_by_identifier(identifier: str) -> Optional[Dict]:
    user = get_user_by_username(identifier)
    if user:
        return user
    return get_user_by_email(identifier)


def create_user(username: str, email: str, password_hash: str):
    return supabase.table("users").insert(
        {
            "username": username,
            "email": email,
            "password_hash": password_hash,
        }
    ).execute()

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

    products_df = load_products_dataframe()

    if products_df.empty and query:
        flash('No products available in Supabase. Please load product data.', 'error')

    if query and not products_df.empty:
        q_lower = query.strip().lower()
        tokens = re.findall(r"[a-z0-9]+", q_lower)
        q_norm = re.sub(r"[^a-z0-9]+", "", q_lower)

        # Strategy 1: All tokens must appear (case-insensitive) in original title
        if tokens:
            mask_all = True
            for t in tokens:
                mask_all = mask_all & products_df['title'].str.contains(re.escape(t), case=False, na=False)
        else:
            mask_all = products_df['title'].str.contains(re.escape(q_lower), case=False, na=False)

        filtered = products_df[mask_all]

        # Strategy 2: If none, try any token in original title
        if filtered.empty and tokens:
            mask_any = False
            for t in tokens:
                mask_any = mask_any | products_df['title'].str.contains(re.escape(t), case=False, na=False)
            filtered = products_df[mask_any]

        # Strategy 3: If still none, try normalized contains on normalized title
        if filtered.empty and q_norm:
            mask_norm = products_df['normalized_title'].str.contains(re.escape(q_norm), na=False)
            filtered = products_df[mask_norm]

        amazon_results = filtered[filtered['platform'].str.lower() == 'amazon'].to_dict(orient='records')
        flipkart_results = filtered[filtered['platform'].str.lower() == 'flipkart'].to_dict(orient='records')

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
        if get_user_by_username(username) or get_user_by_email(email):
            flash('Username or email already exists!')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        try:
            create_user(username=username, email=email, password_hash=hashed_pw)
        except Exception as exc:
            flash(f'Unable to create account: {exc}', 'error')
            return redirect(url_for('register'))

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
        
        user = get_user_by_identifier(username_or_email)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user.get('id')
            session['username'] = user.get('username')
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

        if get_user_by_username(username) or get_user_by_email(email):
            flash('Username or email already exists!', 'error')
            return render_template('signup.html')

        try:
            hashed_pw = generate_password_hash(password)
            create_user(username=username, email=email, password_hash=hashed_pw)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('loginvercel'))
        except Exception as e:
            flash(f'Unable to create account: {str(e)}', 'error')
            return render_template('signup.html')

    return render_template('signup.html')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5050))
    app.run(debug=True, host='0.0.0.0', port=port)
