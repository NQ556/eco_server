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

    try:
        # First, delete existing data
        Product.query.delete()
        Category.query.delete()
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
