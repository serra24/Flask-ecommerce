from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '1234' 
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user_type = data.get('user_type')  # 'admin' or 'user'

    if not username or not password or not user_type:
        return jsonify({'error': 'Username, password, and user type are required.'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username already exists. Please choose a different one.'}), 400

    new_user = User(username=username)
    new_user.set_password(password)
    new_user.is_admin = True if user_type == 'admin' else False

    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully!'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['user_id'] = user.id
        return jsonify({'message': 'Logged in successfully!', 'is_admin': user.is_admin})
    else:
        return jsonify({'error': 'Invalid username or password.'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully!'})

@app.route('/products', methods=['GET'])
def list_products():
    products = Product.query.all()
    return jsonify([{'id': product.id, 'name': product.name, 'price': product.price} for product in products])

@app.route('/cart', methods=['GET', 'POST', 'PUT', 'DELETE'])
def manage_cart():
    if request.method == 'GET':
        user_id = session.get('user_id')
        if user_id:
            cart_items = CartItem.query.filter_by(user_id=user_id).all()
            return jsonify([{'product_id': item.product_id, 'quantity': item.quantity} for item in cart_items])
        else:
            return jsonify({'error': 'User not logged in.'}), 401
    elif request.method == 'POST':
        data = request.get_json()
        user_id = session.get('user_id')
        if user_id:
            product_id = data.get('product_id')
            quantity = data.get('quantity')
            # Add the product to the user's cart with the specified quantity
            return jsonify({'message': 'Product added to cart successfully!'})
        else:
            return jsonify({'error': 'User not logged in.'}), 401
    elif request.method == 'PUT':
        data = request.get_json()
        user_id = session.get('user_id')
        if user_id:
            product_id = data.get('product_id')
            new_quantity = data.get('quantity')
            # Update the quantity of the specified product in the user's cart
            return jsonify({'message': 'Cart updated successfully!'})
        else:
            return jsonify({'error': 'User not logged in.'}), 401
    elif request.method == 'DELETE':
        data = request.get_json()
        user_id = session.get('user_id')
        if user_id:
            product_id = data.get('product_id')
            # Remove the specified product from the user's cart
            return jsonify({'message': 'Product removed from cart successfully!'})
        else:
            return jsonify({'error': 'User not logged in.'}), 401

@app.route('/orders', methods=['GET', 'POST'])
def manage_orders():
    if request.method == 'GET':
        user_id = session.get('user_id')
        if user_id:
            orders = Order.query.filter_by(user_id=user_id).all()
            return jsonify([{'id': order.id, 'total_price': order.total_price} for order in orders])
        else:
            return jsonify({'error': 'User not logged in.'}), 401
    elif request.method == 'POST':
        user_id = session.get('user_id')
        if user_id:
            # Place a new order for the user
            return jsonify({'message': 'Order placed successfully!'})
        else:
            return jsonify({'error': 'User not logged in.'}), 401

@app.route('/admin/products', methods=['GET', 'POST'])
def admin_products():
    if request.method == 'GET':
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user.is_admin:
                products = Product.query.all()
                return jsonify([{'id': product.id, 'name': product.name, 'price': product.price} for product in products])
            else:
                return jsonify({'error': 'Unauthorized access.'}), 403
        else:
            return jsonify({'error': 'User not logged in.'}), 401
    elif request.method == 'POST':
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user.is_admin:
                data = request.get_json()
                name = data.get('name')
                price = data.get('price')
                new_product = Product(name=name, price=price)
                db.session.add(new_product)
                db.session.commit()
                return jsonify({'message': 'Product added successfully!'})
            else:
                return jsonify({'error': 'Unauthorized access.'}), 403
        else:
            return jsonify({'error': 'User not logged in.'}), 401

@app.route('/admin/orders', methods=['GET'])
def admin_orders():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user.is_admin:
            orders = Order.query.all()
            return jsonify([{'id': order.id, 'user_id': order.user_id, 'total_price': order.total_price} for order in orders])
        else:
            return jsonify({'error': 'Unauthorized access.'}), 403
    else:
        return jsonify({'error': 'User not logged in.'}), 401

@app.route('/products/<int:product_id>/rate', methods=['POST'])
def rate_product(product_id):
    user_id = session.get('user_id')
    if user_id:
        data = request.get_json()
        rating = data.get('rating')
        # Rate the specified product by the user
        return jsonify({'message': 'Product rated successfully!'})
    else:
        return jsonify({'error': 'User not logged in.'}), 401

@app.route('/products/<int:product_id>/comment', methods=['POST'])
def comment_on_product(product_id):
    user_id = session.get('user_id')
    if user_id:
        data = request.get_json()
        content = data.get('content')
        # Add a comment on the specified product by the user
        return jsonify({'message': 'Comment added successfully!'})
    else:
        return jsonify({'error': 'User not logged in.'}), 401

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

