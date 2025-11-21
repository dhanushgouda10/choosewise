import pandas as pd
from flask import Flask, render_template, request

app = Flask(__name__)

# ✅ Read CSV files instead
amazon_df = pd.read_csv("merged_amazon.csv")
flipkart_df = pd.read_csv("merged_flipkart.csv")

# Modify these column names as per your CSV headers
amazon_data = pd.DataFrame({
    'platform': 'Amazon',
    'link': amazon_df['single-href'],
    'title': amazon_df['title'],
    'price': amazon_df['price'],
    'image': amazon_df['image-src'],
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

@app.route('/', methods=['GET', 'POST'])
def index():
    query = request.form.get('query', '')
    amazon_results = []
    flipkart_results = []

    if query:
        filtered = all_products[all_products['title'].str.contains(query, case=False, na=False)]
        amazon_results = filtered[filtered['platform'] == 'Amazon'].to_dict(orient='records')
        flipkart_results = filtered[filtered['platform'] == 'Flipkart'].to_dict(orient='records')

    return render_template('index.html', 
                         amazon_products=amazon_results, 
                         flipkart_products=flipkart_results, 
                         query=query)

if __name__ == '__main__':
    app.run(debug=True)
