# app.py
import streamlit as st
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
from datetime import datetime

st.set_page_config("Streamlit Shop (MongoDB)", layout="wide")

# ---------------------------
# DB connection via st.secrets
# st.secrets should contain:
# st.secrets["mongo"]["uri"]
# st.secrets["mongo"]["db"]
# and admin credentials:
# st.secrets["admin"]["username"]
# st.secrets["admin"]["password"]
# ---------------------------

@st.cache_resource
def get_db():
    uri = st.secrets["mongo"]["uri"]
    db_name = st.secrets["mongo"]["db"]
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    db = client[db_name]
    return db

try:
    db = get_db()
    users_col = db["users"]       # documents: {"username":..., "password_hash":...}
    products_col = db["products"] # documents: {"name":..., "price": float}
    orders_col = db["orders"]     # documents: {"username":..., "items":[{"product_id":..., "name":..., "price":..., "qty":...}], "total":..., "ts":...}
except Exception as e:
    st.error("Couldn't connect to the database. Check your Streamlit secrets and network.")
    st.stop()

# ---------------------------
# Utilities
# ---------------------------
def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain_password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed.encode())
    except Exception:
        return False

def create_user_in_db(username: str, password: str) -> bool:
    if users_col.find_one({"username": username}):
        return False
    password_hash = hash_password(password)
    users_col.insert_one({"username": username, "password_hash": password_hash})
    return True

def create_product_in_db(name: str, price: float):
    products_col.insert_one({"name": name, "price": float(price)})

def fetch_products():
    docs = list(products_col.find({}))
    for d in docs:
        d["id"] = str(d["_id"])
    return docs

def fetch_users():
    docs = list(users_col.find({}, {"username":1}))
    for d in docs:
        d["id"] = str(d["_id"])
    return docs

# ---------------------------
# Session state init
# ---------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None  # "admin" or "user"
    st.session_state.username = None
    st.session_state.cart = {}    # product_id -> {"name":..., "price":..., "qty":...}

# ---------------------------
# Authentication UI
# ---------------------------
st.title("🛍️ Simple Streamlit Shop (MongoDB-backed)")

page = st.radio("Choose", ["Login"], index=0, horizontal=True)

with st.expander("App info / instructions", expanded=False):
    st.write("""
    - Admin credentials are stored in Streamlit secrets (see `.streamlit/secrets.toml` example).
    - Admin can create users and add products.
    - Users sign in with the credentials created by Admin.
    - Users can add products to a cart and click **Buy** to place an order (stored in MongoDB).
    """)

# Login form
st.subheader("Login")
col1, col2 = st.columns(2)
with col1:
    role = st.selectbox("Login as", ["Admin", "User"])
with col2:
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

if st.button("Login"):
    if role == "Admin":
        admin_user = st.secrets.get("admin", {}).get("username")
        admin_pass = st.secrets.get("admin", {}).get("password")
        if admin_user is None or admin_pass is None:
            st.error("Admin credentials not configured in secrets. See README / secrets.toml example.")
        elif username == admin_user and password == admin_pass:
            st.session_state.logged_in = True
            st.session_state.role = "admin"
            st.session_state.username = username
            st.success("Admin logged in")
        else:
            st.error("Invalid admin credentials.")
    else:  # User login
        doc = users_col.find_one({"username": username})
        if not doc:
            st.error("User not found. Contact admin to create an account.")
        else:
            if verify_password(password, doc.get("password_hash", "")):
                st.session_state.logged_in = True
                st.session_state.role = "user"
                st.session_state.username = username
                st.success(f"User {username} logged in")
            else:
                st.error("Incorrect password.")

# ---------------------------
# Logout button
# ---------------------------
if st.session_state.logged_in:
    st.sidebar.write(f"Logged in as: **{st.session_state.username}** ({st.session_state.role})")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.role = None
        st.session_state.username = None
        st.session_state.cart = {}
        st.experimental_rerun()

# ---------------------------
# Admin area
# ---------------------------
if st.session_state.logged_in and st.session_state.role == "admin":
    st.header("Admin Panel")
    tab1, tab2, tab3 = st.tabs(["Create User", "Create Product", "View Data"])

    with tab1:
        st.subheader("Create User (for customers)")
        new_username = st.text_input("New user's username", key="new_user_username")
        new_password = st.text_input("New user's password", type="password", key="new_user_password")
        if st.button("Create user"):
            if not new_username or not new_password:
                st.warning("Enter both username and password.")
            else:
                ok = create_user_in_db(new_username, new_password)
                if ok:
                    st.success(f"Created user `{new_username}`")
                else:
                    st.error("Username already exists. Choose another username.")

    with tab2:
        st.subheader("Create Product")
        prod_name = st.text_input("Product name", key="prod_name")
        prod_price = st.number_input("Price (INR)", min_value=0.0, format="%.2f", key="prod_price")
        if st.button("Add product"):
            if not prod_name:
                st.warning("Enter a product name.")
            else:
                create_product_in_db(prod_name, prod_price)
                st.success(f"Product `{prod_name}` added at price {prod_price:.2f}")

    with tab3:
        st.subheader("View / Delete Data")
        st.markdown("**Products**")
        products = fetch_products()
        if products:
            for p in products:
                cols = st.columns([4,2,1])
                cols[0].write(p["name"])
                cols[1].write(f"₹{p['price']:.2f}")
                if cols[2].button("Delete", key=f"delprod_{p['id']}"):
                    products_col.delete_one({"_id": ObjectId(p["id"])})
                    st.experimental_rerun()
        else:
            st.info("No products yet.")

        st.markdown("---")
        st.markdown("**Users**")
        users = fetch_users()
        if users:
            for u in users:
                cols = st.columns([6,2])
                cols[0].write(u["username"])
                if cols[1].button("Delete", key=f"deluser_{u['id']}"):
                    users_col.delete_one({"_id": ObjectId(u["id"])})
                    st.experimental_rerun()
        else:
            st.info("No users yet.")

# ---------------------------
# User area (after login)
# ---------------------------
if st.session_state.logged_in and st.session_state.role == "user":
    st.header("Shop - Products")
    products = fetch_products()

    if not products:
        st.info("No products available. Contact admin.")
    else:
        # Products listing
        for p in products:
            cols = st.columns([4,2,2])
            cols[0].markdown(f"**{p['name']}**")
            cols[1].markdown(f"₹{p['price']:.2f}")
            if cols[2].button("Add to cart", key=f"add_{p['id']}"):
                pid = p["id"]
                cart = st.session_state.cart
                if pid in cart:
                    cart[pid]["qty"] += 1
                else:
                    cart[pid] = {"name": p["name"], "price": p["price"], "qty": 1}
                st.success(f"Added {p['name']} to cart")

    st.markdown("---")
    st.subheader("Your Cart")
    if not st.session_state.cart:
        st.write("Cart is empty")
    else:
        total = 0.0
        for pid, item in st.session_state.cart.items():
            cols = st.columns([4,2,2,1])
            cols[0].write(item["name"])
            cols[1].write(f"₹{item['price']:.2f} x {item['qty']}")
            item_total = item["price"] * item["qty"]
            cols[2].write(f"₹{item_total:.2f}")
            total += item_total
            if cols[3].button("Remove one", key=f"remove_{pid}"):
                if item["qty"] > 1:
                    item["qty"] -= 1
                else:
                    del st.session_state.cart[pid]
                st.experimental_rerun()
        st.markdown(f"**Total: ₹{total:.2f}**")

        if st.button("Buy"):
            # Prepare order doc
            items = []
            for pid, item in st.session_state.cart.items():
                items.append({
                    "product_id": pid,
                    "name": item["name"],
                    "price": float(item["price"]),
                    "qty": int(item["qty"])
                })
            order = {
                "username": st.session_state.username,
                "items": items,
                "total": float(total),
                "ts": datetime.utcnow()
            }
            orders_col.insert_one(order)
            st.success("Order placed successfully ✅")
            # clear cart
            st.session_state.cart = {}
            st.experimental_rerun()

# ---------------------------
# Non-logged in / guest prompt
# ---------------------------
if not st.session_state.logged_in:
    st.info("Please log in as Admin or User to continue.")
