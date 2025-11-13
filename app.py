import streamlit as st
from pymongo import MongoClient

# -------------------------------
# 1️⃣ MongoDB Connection
# -------------------------------
MONGODB_URI = "mongodb+srv://aagyabajpai2005_db_user:aagya@cluster08.q42obrr.mongodb.net/streamlit_shop_db?retryWrites=true&w=majority"
client = MongoClient(MONGODB_URI)
db = client["streamlit_shop_db"]

# -------------------------------
# 2️⃣ Admin Credentials (Hardcoded)
# -------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# -------------------------------
# 3️⃣ Helper functions
# -------------------------------
def create_user(username, password):
    """Add a new user"""
    users = db["users"]
    if users.find_one({"username": username}):
        st.warning("User already exists!")
    else:
        users.insert_one({"username": username, "password": password})
        st.success("✅ User created successfully!")

def add_product(name, price):
    """Add a new product"""
    products = db["products"]
    products.insert_one({"name": name, "price": price})
    st.success("✅ Product added successfully!")

def get_products():
    """Fetch all products"""
    return list(db["products"].find())

# -------------------------------
# 4️⃣ Streamlit App UI
# -------------------------------
st.title("🛍️ Online Product Store")

# Tabs for login type
login_type = st.sidebar.radio("Login as:", ["Admin", "User"])

if login_type == "Admin":
    st.subheader("🔐 Admin Login")
    username = st.text_input("Admin Username")
    password = st.text_input("Admin Password", type="password")

    if st.button("Login"):
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            st.success("✅ Admin logged in successfully!")

            st.header("👤 Create New User")
            new_user = st.text_input("Enter new username")
            new_pass = st.text_input("Enter new password", type="password")
            if st.button("Create User"):
                create_user(new_user, new_pass)

            st.header("📦 Add Product")
            product_name = st.text_input("Product name")
            product_price = st.number_input("Price", min_value=0.0)
            if st.button("Add Product"):
                add_product(product_name, product_price)
        else:
            st.error("❌ Invalid admin credentials")

# -------------------------------
# USER LOGIN
# -------------------------------
else:
    st.subheader("👤 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = db["users"].find_one({"username": username, "password": password})
        if user:
            st.success(f"✅ Welcome {username}!")
            st.header("🛒 Products Available")

            products = get_products()
            cart = []
            for product in products:
                if st.checkbox(f"{product['name']} - ₹{product['price']}"):
                    cart.append(product)

            if st.button("Buy"):
                if cart:
                    db["orders"].insert_one({"user": username, "items": cart})
                    st.success("🎉 Order placed successfully!")
                else:
                    st.warning("🛍️ Please select at least one product.")
        else:
            st.error("❌ Invalid username or password")
