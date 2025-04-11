from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt
from functools import wraps
import os

# App
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://localhost:3000"]}})

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', '').replace("postgres://", "postgresql://")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret Key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock_quantity = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.Text, nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    excerpt = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(10), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    read_time = db.Column(db.String(20), nullable=False)
    image = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    tags = db.Column(db.JSON, nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.Column(db.String(100), nullable=False)

# Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({"message": "Token is invalid!"}), 403
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            
            if not current_user.is_admin:
                return jsonify({"message": "Admin privileges required!"}), 403
                
        except:
            return jsonify({"message": "Token is invalid!"}), 403
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Auth Routes
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already registered"}), 400
        
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already taken"}), 400
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        email=data['email'],
        username=data['username'],
        password=hashed_password,
        is_admin=data.get('is_admin', False)
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    token = jwt.encode({
        'user_id': new_user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        "message": "User registered successfully",
        "token": token,
        "user": {
            "id": new_user.id,
            "email": new_user.email,
            "username": new_user.username,
            "is_admin": new_user.is_admin
        }
    }), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "is_admin": user.is_admin
            }
        }), 200
    
    return jsonify({"message": "Invalid credentials"}), 401

# Product Routes
@app.route('/products', methods=['GET'])
def get_products():
    category_id = request.args.get('category_id')
    
    if category_id:
        products = Product.query.filter_by(category_id=category_id).all()
    else:
        products = Product.query.all()
    
    return jsonify([{
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "price": p.price,
        "stock_quantity": p.stock_quantity,
        "image_url": p.image_url,
        "category_id": p.category_id,
        "category_name": p.category.name
    } for p in products]), 200

@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    return jsonify({
        "id": product.id,
        "name": product.name,
        "description": product.description,
        "price": product.price,
        "stock_quantity": product.stock_quantity,
        "image_url": product.image_url,
        "category_id": product.category_id,
        "category_name": product.category.name
    }), 200

@app.route('/products', methods=['POST'])
@admin_required
def create_product(current_user):
    data = request.get_json()
    
    new_product = Product(
        name=data['name'],
        description=data['description'],
        price=data['price'],
        stock_quantity=data['stock_quantity'],
        image_url=data.get('image_url'),
        category_id=data['category_id']
    )
    
    db.session.add(new_product)
    db.session.commit()
    
    return jsonify({
        "message": "Product created successfully",
        "product": {
            "id": new_product.id,
            "name": new_product.name,
            "description": new_product.description,
            "price": new_product.price,
            "stock_quantity": new_product.stock_quantity,
            "image_url": new_product.image_url,
            "category_id": new_product.category_id
        }
    }), 201

# Category Routes
@app.route('/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    return jsonify([{
        "id": c.id,
        "name": c.name
    } for c in categories]), 200

@app.route('/categories', methods=['POST'])
@admin_required
def create_category(current_user):
    data = request.get_json()
    
    if Category.query.filter_by(name=data['name']).first():
        return jsonify({"message": "Category already exists"}), 400
    
    new_category = Category(name=data['name'])
    db.session.add(new_category)
    db.session.commit()
    
    return jsonify({
        "message": "Category created successfully",
        "category": {
            "id": new_category.id,
            "name": new_category.name
        }
    }), 201

# Blog Routes
@app.route('/blog/posts', methods=['GET'])
def get_blog_posts():
    category = request.args.get('category')
    tag = request.args.get('tag')
    
    query = BlogPost.query
    
    if category:
        query = query.filter_by(category=category)
    
    if tag:
        query = query.filter(BlogPost.tags.contains([tag]))
    
    posts = query.order_by(BlogPost.date.desc()).all()
    
    return jsonify([{
        "id": post.id,
        "title": post.title,
        "excerpt": post.excerpt,
        "content": post.content,
        "date": post.date,
        "author": post.author,
        "readTime": post.read_time,
        "image": post.image,
        "category": post.category,
        "tags": post.tags
    } for post in posts]), 200

@app.route('/blog/posts/<int:post_id>', methods=['GET'])
def get_blog_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    
    return jsonify({
        "id": post.id,
        "title": post.title,
        "excerpt": post.excerpt,
        "content": post.content,
        "date": post.date,
        "author": post.author,
        "readTime": post.read_time,
        "image": post.image,
        "category": post.category,
        "tags": post.tags
    }), 200

@app.route('/blog/posts', methods=['POST'])
@admin_required
def create_blog_post(current_user):
    data = request.get_json()
    
    new_post = BlogPost(
        title=data['title'],
        excerpt=data['excerpt'],
        content=data['content'],
        date=data['date'],
        author=data['author'],
        read_time=data['readTime'],
        image=data['image'],
        category=data['category'],
        tags=data['tags']
    )
    
    db.session.add(new_post)
    db.session.commit()
    
    return jsonify({
        "message": "Blog post created successfully",
        "post": {
            "id": new_post.id,
            "title": new_post.title,
            "excerpt": new_post.excerpt,
            "content": new_post.content,
            "date": new_post.date,
            "author": new_post.author,
            "readTime": new_post.read_time,
            "image": new_post.image,
            "category": new_post.category,
            "tags": new_post.tags
        }
    }), 201

@app.route('/blog/categories', methods=['GET'])
def get_blog_categories():
    categories = db.session.query(BlogPost.category).distinct().all()
    return jsonify([category[0] for category in categories]), 200

@app.route('/blog/tags', methods=['GET'])
def get_blog_tags():
    posts = BlogPost.query.all()
    all_tags = set()
    for post in posts:
        all_tags.update(post.tags)
    return jsonify(list(all_tags)), 200

@app.route('/blog/posts/<int:post_id>/comments', methods=['GET'])
def get_post_comments(post_id):
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.desc()).all()
    return jsonify([{
        "id": comment.id,
        "content": comment.content,
        "created_at": comment.created_at.isoformat(),
        "author": comment.author,
    } for comment in comments]), 200

@app.route('/blog/posts/<int:post_id>/comments', methods=['POST'])
@token_required
def create_comment(current_user, post_id):
    data = request.get_json()
    
    if not data.get('content'):
        return jsonify({"message": "Comment content is required"}), 400
    
    new_comment = Comment(
        content=data['content'],
        post_id=post_id,
        user_id=current_user.id,
        author=current_user.username
    )
    
    db.session.add(new_comment)
    db.session.commit()
    
    return jsonify({
        "id": new_comment.id,
        "content": new_comment.content,
        "created_at": new_comment.created_at.isoformat(),
        "author": new_comment.author,
    }), 201

# Data initialization function
def populate_db():
    # Create categories
    categories_data = [
        {"id": 1, "name": "Living Room"},
        {"id": 2, "name": "Bedroom"},
        {"id": 3, "name": "Dining Room"},
        {"id": 4, "name": "Office"},
        {"id": 5, "name": "Outdoor"},
        {"id": 6, "name": "Kitchen"},
        {"id": 7, "name": "Bathroom"}
    ]
    
    # Create products
    products_data = [
        {
            "id": 1,
            "name": "Modern Sectional Sofa",
            "description": "A spacious L-shaped sectional sofa with plush cushions and durable fabric upholstery. Perfect for family gatherings and entertaining guests.",
            "price": 1299.99,
            "stock_quantity": 15,
            "image_url": "https://m.media-amazon.com/images/I/91x5nH56ZZL.jpg",
            "category_id": 1
        },
        {
            "id": 2,
            "name": "Leather Recliner",
            "description": "Premium leather recliner with adjustable positions and built-in cup holders. Offers exceptional comfort for relaxation.",
            "price": 849.99,
            "stock_quantity": 8,
            "image_url": "https://m.media-amazon.com/images/I/71xwaQExooL._AC_SL1500_.jpg",
            "category_id": 1
        },
        {
            "id": 3,
            "name": "Coffee Table with Storage",
            "description": "Elegant wooden coffee table with hidden storage compartments. Features a lift-top design for versatile use.",
            "price": 349.99,
            "stock_quantity": 22,
            "image_url": "https://m.media-amazon.com/images/I/81WeJ37mUaL._AC_SL1500_.jpg",
            "category_id": 1
        },
        {
            "id": 4,
            "name": "King Size Platform Bed",
            "description": "Contemporary platform bed with integrated headboard and solid wood frame. No box spring required.",
            "price": 799.99,
            "stock_quantity": 12,
            "image_url": "https://m.media-amazon.com/images/I/71VWGn1Dx6L._AC_SL1500_.jpg",
            "category_id": 2
        },
        {
            "id": 5,
            "name": "Memory Foam Mattress",
            "description": "Queen size memory foam mattress with cooling gel technology. Provides optimal support and temperature regulation for quality sleep.",
            "price": 699.99,
            "stock_quantity": 30,
            "image_url": "https://m.media-amazon.com/images/I/91m32IzW-lL._AC_SL1500_.jpg",
            "category_id": 2
        },
        {
            "id": 6,
            "name": "Nightstand with Charging Station",
            "description": "Compact bedside table with built-in USB ports and wireless charging pad. Includes two drawers for storage.",
            "price": 199.99,
            "stock_quantity": 25,
            "image_url": "https://m.media-amazon.com/images/I/711fVS2ix3L._AC_SL1500_.jpg",
            "category_id": 2
        },
        {
            "id": 7,
            "name": "Extending Dining Table",
            "description": "Solid oak dining table with extension leaves. Can accommodate 6-10 people when fully extended.",
            "price": 899.99,
            "stock_quantity": 10,
            "image_url": "https://m.media-amazon.com/images/I/71hRED5bl7L._AC_SL1200_.jpg",
            "category_id": 3
        },
        {
            "id": 8,
            "name": "Upholstered Dining Chairs (Set of 4)",
            "description": "Set of four dining chairs with padded seats and backrests. Features sturdy wooden legs and elegant fabric upholstery.",
            "price": 499.99,
            "stock_quantity": 18,
            "image_url": "https://m.media-amazon.com/images/I/71aJAdltM+L._AC_SL1500_.jpg",
            "category_id": 3
        },
        {
            "id": 9,
            "name": "China Cabinet",
            "description": "Traditional china cabinet with glass doors and interior lighting. Perfect for displaying fine dinnerware and collectibles.",
            "price": 1099.99,
            "stock_quantity": 5,
            "image_url": "https://m.media-amazon.com/images/I/71fyIMN56kL._AC_SL1500_.jpg",
            "category_id": 3
        },
        {
            "id": 10,
            "name": "Executive Desk",
            "description": "Spacious executive desk with multiple drawers and cable management system. Made from sustainable hardwood with a premium finish.",
            "price": 749.99,
            "stock_quantity": 7,
            "image_url": "https://m.media-amazon.com/images/I/81Lu6JijCHL._AC_SL1500_.jpg",
            "category_id": 4
        },
        {
            "id": 11,
            "name": "Ergonomic Office Chair",
            "description": "Fully adjustable office chair with lumbar support and breathable mesh back. Designed for all-day comfort.",
            "price": 299.99,
            "stock_quantity": 20,
            "image_url": "https://m.media-amazon.com/images/I/81GfB85DaoL._AC_SL1500_.jpg",
            "category_id": 4
        },
        {
            "id": 12,
            "name": "Bookshelf with Cabinet",
            "description": "Versatile bookshelf with open shelving and closed cabinet storage. Perfect for organizing books and office supplies.",
            "price": 249.99,
            "stock_quantity": 15,
            "image_url": "https://m.media-amazon.com/images/I/7137bps9j7L._AC_SL1500_.jpg",
            "category_id": 4
        },
        {
            "id": 13,
            "name": "Patio Dining Set",
            "description": "Weather-resistant 6-piece patio dining set including table, chairs, and umbrella. Perfect for outdoor entertaining.",
            "price": 899.99,
            "stock_quantity": 8,
            "image_url": "https://m.media-amazon.com/images/I/81-0hiIiIhL._AC_SL1500_.jpg",
            "category_id": 5
        },
        {
            "id": 14,
            "name": "Adirondack Chair",
            "description": "Classic Adirondack chair made from weather-resistant recycled plastic. Maintenance-free and available in multiple colors.",
            "price": 179.99,
            "stock_quantity": 30,
            "image_url": "https://m.media-amazon.com/images/I/716R9MUVnKL._AC_SL1500_.jpg",
            "category_id": 5
        },
        {
            "id": 15,
            "name": "Outdoor Storage Bench",
            "description": "Multipurpose outdoor bench with hidden storage compartment. Ideal for patio cushions and garden accessories.",
            "price": 249.99,
            "stock_quantity": 12,
            "image_url": "https://m.media-amazon.com/images/I/81F8ilSpD2L._AC_SL1500_.jpg",
            "category_id": 5
        },
        {
            "id": 16,
            "name": "Kitchen Cabinet Set",
            "description": "Complete set of modern kitchen cabinets with soft-close drawers and elegant hardware. Includes upper and lower cabinets.",
            "price": 2499.99,
            "stock_quantity": 5,
            "image_url": "https://m.media-amazon.com/images/I/716d9+An+pL._AC_SL1500_.jpg",
            "category_id": 6
        }
    ]

    # Create blog posts
    blog_posts_data = [
        {
            "id": 1,
            "title": "Sustainable Living Tips",
            "excerpt": "Simple ways to reduce your environmental impact in daily life. Learn how small changes in your daily routine can make a big difference for our planet.",
            "content": "Living sustainably doesn't have to be complicated or overwhelming. Small changes in our daily routines can collectively make a significant impact on our environment. Here are some practical tips to get started:\n\n1. Reduce Single-Use Plastics\n- Carry reusable shopping bags\n- Use a refillable water bottle\n- Invest in reusable food containers\n\n2. Save Energy at Home\n- Switch to LED bulbs\n- Unplug electronics when not in use\n- Use natural light when possible\n\n3. Minimize Water Waste\n- Fix leaky faucets\n- Install water-efficient fixtures\n- Collect rainwater for plants\n\n4. Practice Sustainable Shopping\n- Buy local and seasonal products\n- Choose products with minimal packaging\n- Support eco-friendly brands\n\nRemember, sustainable living is a journey, not a destination. Start with small changes and gradually incorporate more eco-friendly practices into your lifestyle.",
            "date": "2024-03-20",
            "author": "Emma Green",
            "read_time": "5 min",
            "image": "https://images.unsplash.com/photo-1542601906990-b4d3fb778b09?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1313&q=80",
            "category": "Lifestyle",
            "tags": ["sustainability", "eco-friendly", "lifestyle", "environment"]
        },
        {
            "id": 2,
            "title": "Understanding Carbon Footprint",
            "excerpt": "Learn how your daily choices affect the environment and what steps you can take to reduce your carbon footprint for a more sustainable future.",
            "content": "Your carbon footprint is the total amount of greenhouse gases generated by your actions. Understanding and reducing it is crucial for combating climate change.\n\nWhat Contributes to Your Carbon Footprint?\n\n1. Transportation\n- Daily commuting\n- Air travel\n- Personal vehicle use\n\n2. Home Energy Use\n- Heating and cooling\n- Electricity consumption\n- Appliance efficiency\n\n3. Food Choices\n- Meat consumption\n- Food waste\n- Packaging waste\n\n4. Consumer Habits\n- Fast fashion\n- Electronic devices\n- Single-use products\n\nHow to Reduce Your Carbon Footprint:\n\n1. Choose sustainable transportation options\n2. Improve home energy efficiency\n3. Adopt a plant-based diet\n4. Practice mindful consumption\n\nCalculating and reducing your carbon footprint is an ongoing process that requires awareness and commitment to sustainable choices.",
            "date": "2024-03-18",
            "author": "Dr. Michael Chen",
            "read_time": "7 min",
            "image": "https://images.unsplash.com/photo-1550745165-9bc0b252726f?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1470&q=80",
            "category": "Education",
            "tags": ["carbon footprint", "climate change", "sustainability", "environment"]
        },
        {
            "id": 3,
            "title": "Eco-Friendly Home Decor Ideas",
            "excerpt": "Discover creative ways to decorate your home while being environmentally conscious. From upcycled furniture to sustainable materials.",
            "content": "Creating an eco-friendly home doesn't mean sacrificing style. Here's how to make your space both beautiful and sustainable:\n\n1. Sustainable Materials\n- Bamboo furniture\n- Recycled glass decorations\n- Natural fiber textiles\n\n2. Upcycling Projects\n- Repurposed furniture\n- DIY art from reclaimed materials\n- Vintage decor items\n\n3. Indoor Plants\n- Air-purifying varieties\n- Vertical gardens\n- Herb gardens\n\n4. Energy-Efficient Lighting\n- LED fixtures\n- Natural light optimization\n- Solar-powered options\n\nTips for Sustainable Decorating:\n- Shop second-hand first\n- Choose quality over quantity\n- Support local artisans\n- Use non-toxic finishes and paints\n\nRemember that sustainable decor is about making conscious choices that benefit both your home and the environment.",
            "date": "2024-03-15",
            "author": "Sofia Martinez",
            "read_time": "6 min",
            "image": "https://images.unsplash.com/photo-1556228453-efd6c1ff04f6?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1470&q=80",
            "category": "Interior Design",
            "tags": ["interior design", "sustainable living", "home decor", "DIY"]
        },
        {
            "id": 4,
            "title": "The Rise of Sustainable Furniture",
            "excerpt": "Explore the growing trend of sustainable furniture and how manufacturers are adopting eco-friendly practices in production.",
            "content": "The furniture industry is undergoing a significant transformation as sustainability becomes a key focus. This shift is driven by both consumer demand and environmental necessity.\n\n1. Sustainable Materials\n- Reclaimed wood\n- Bamboo and fast-growing materials\n- Recycled metals and plastics\n\n2. Manufacturing Practices\n- Zero-waste production\n- Renewable energy usage\n- Local sourcing\n\n3. Circular Economy\n- Take-back programs\n- Furniture refurbishment\n- End-of-life recycling\n\n4. Industry Innovation\n- Bio-based materials\n- Modular design\n- 3D printing\n\nThe future of furniture manufacturing lies in sustainable practices that benefit both consumers and the environment. Companies leading this change are setting new standards for the industry.",
            "date": "2024-03-12",
            "author": "James Wilson",
            "read_time": "8 min",
            "image": "https://images.unsplash.com/photo-1538688525198-9b88f6f53126?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1374&q=80",
            "category": "Industry News",
            "tags": ["furniture", "sustainability", "manufacturing", "industry"]
        },
        {
            "id": 5,
            "title": "Zero Waste Living Guide",
            "excerpt": "A comprehensive guide to starting your zero waste journey. Tips, tricks, and product recommendations for a waste-free lifestyle.",
            "content": "Transitioning to a zero waste lifestyle is a powerful way to reduce your environmental impact. Here's your comprehensive guide to getting started:\n\n1. Kitchen Essentials\n- Reusable containers\n- Cloth produce bags\n- Composting system\n\n2. Bathroom Swaps\n- Bar soaps and shampoos\n- Bamboo toothbrush\n- Reusable cotton rounds\n\n3. Shopping Habits\n- Bulk store shopping\n- Farmers markets\n- Package-free stores\n\n4. Waste Reduction Strategies\n- Meal planning\n- Repair instead of replace\n- Digital over paper\n\nRemember that zero waste is about progress, not perfection. Every small change contributes to a larger environmental impact.",
            "date": "2024-03-10",
            "author": "Lisa Chang",
            "read_time": "6 min",
            "image": "https://images.unsplash.com/photo-1542601906990-b4d3fb778b09?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1313&q=80",
            "category": "Lifestyle",
            "tags": ["zero waste", "sustainability", "lifestyle", "environment"]
        },
        {
            "id": 6,
            "title": "Sustainable Materials in Modern Design",
            "excerpt": "An in-depth look at how sustainable materials are being incorporated into modern furniture design without compromising style.",
            "content": "Modern design is embracing sustainability like never before, proving that eco-friendly materials can create stunning and functional pieces:\n\n1. Innovative Materials\n- Mycelium-based products\n- Ocean plastic furniture\n- Recycled composite materials\n\n2. Design Principles\n- Minimalist approach\n- Multi-functional pieces\n- Timeless aesthetics\n\n3. Material Processing\n- Low-impact manufacturing\n- Natural finishing techniques\n- Waste reduction methods\n\n4. Future Trends\n- Smart sustainable materials\n- Self-repairing surfaces\n- Biodegradable furniture\n\nThe fusion of sustainable materials with modern design is creating a new paradigm in furniture manufacturing, where style meets responsibility.",
            "date": "2024-03-08",
            "author": "Alex Rivera",
            "read_time": "7 min",
            "image": "https://images.unsplash.com/photo-1538688525198-9b88f6f53126?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1374&q=80",
            "category": "Design",
            "tags": ["design", "materials", "sustainability", "furniture"]
        }
    ]

    try:
        # First, delete existing data
        Product.query.delete()
        Category.query.delete()
        BlogPost.query.delete()
        Comment.query.delete()
        db.session.commit()

        # Add categories
        for cat_data in categories_data:
            category = Category(id=cat_data['id'], name=cat_data['name'])
            db.session.add(category)
        db.session.commit()

        # Add products
        for prod_data in products_data:
            product = Product(
                id=prod_data['id'],
                name=prod_data['name'],
                description=prod_data['description'],
                price=prod_data['price'],
                stock_quantity=prod_data['stock_quantity'],
                image_url=prod_data['image_url'],
                category_id=prod_data['category_id']
            )
            db.session.add(product)
        db.session.commit()

        # Add blog posts
        for post_data in blog_posts_data:
            post = BlogPost(
                id=post_data['id'],
                title=post_data['title'],
                excerpt=post_data['excerpt'],
                content=post_data['content'],
                date=post_data['date'],
                author=post_data['author'],
                read_time=post_data['read_time'],
                image=post_data['image'],
                category=post_data['category'],
                tags=post_data['tags']
            )
            db.session.add(post)
        db.session.commit()

        print("Database populated successfully!")
        return True
    except Exception as e:
        print(f"Error populating database: {str(e)}")
        db.session.rollback()
        return False

# Initialize DB
with app.app_context():
    db.create_all()
    populate_db()  # Call the populate function after creating tables

# Run the server
if __name__ == '__main__':
    app.run(debug=True) 
