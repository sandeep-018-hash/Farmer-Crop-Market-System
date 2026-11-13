import os
import re
import math
import sqlite3
import secrets
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    g,
)
from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DB_NAME = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "farmer_market.db"
)


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def table_columns(conn, table_name):
    return {
        row["name"]
        for row in conn.execute(
            f"PRAGMA table_info({table_name})"
        ).fetchall()
    }


# --------------------------------------------------
# DATABASE INITIALIZATION AND SAFE MIGRATIONS
# --------------------------------------------------

def init_db():
    conn = get_db()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                farmer_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS farmer_crops (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                farmer_name TEXT NOT NULL,
                crop TEXT NOT NULL,
                quantity REAL NOT NULL DEFAULT 0,
                location TEXT NOT NULL,
                expected_price REAL NOT NULL DEFAULT 0
            )
        """)

        crop_columns = table_columns(conn, "farmer_crops")

        if "phone_number" not in crop_columns:
            conn.execute("""
                ALTER TABLE farmer_crops
                ADD COLUMN phone_number TEXT NOT NULL DEFAULT ''
            """)

        if "market_name" not in crop_columns:
            conn.execute("""
                ALTER TABLE farmer_crops
                ADD COLUMN market_name TEXT NOT NULL DEFAULT ''
            """)

        if "owner_user_id" not in crop_columns:
            conn.execute("""
                ALTER TABLE farmer_crops
                ADD COLUMN owner_user_id INTEGER
            """)

        # Assign old crops only when exactly one user matches the farmer name.
        # Ambiguous or unmatched old records remain unassigned.
        conn.execute("""
            UPDATE farmer_crops
            SET owner_user_id = (
                SELECT MIN(users.id)
                FROM users
                WHERE LOWER(TRIM(users.farmer_name)) =
                      LOWER(TRIM(farmer_crops.farmer_name))
            )
            WHERE owner_user_id IS NULL
              AND (
                  SELECT COUNT(*)
                  FROM users
                  WHERE LOWER(TRIM(users.farmer_name)) =
                        LOWER(TRIM(farmer_crops.farmer_name))
              ) = 1
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                crop_id INTEGER,
                crop_name TEXT NOT NULL,
                farmer_name TEXT NOT NULL,
                customer_name TEXT NOT NULL,
                customer_phone TEXT NOT NULL,
                quantity REAL NOT NULL,
                price_per_kg REAL NOT NULL,
                total_amount REAL NOT NULL,
                purchase_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        purchase_columns = table_columns(conn, "purchases")

        if "owner_user_id" not in purchase_columns:
            conn.execute("""
                ALTER TABLE purchases
                ADD COLUMN owner_user_id INTEGER
            """)

        # Assign old purchases only when exactly one user matches the farmer name.
        conn.execute("""
            UPDATE purchases
            SET owner_user_id = (
                SELECT MIN(users.id)
                FROM users
                WHERE LOWER(TRIM(users.farmer_name)) =
                      LOWER(TRIM(purchases.farmer_name))
            )
            WHERE owner_user_id IS NULL
              AND (
                  SELECT COUNT(*)
                  FROM users
                  WHERE LOWER(TRIM(users.farmer_name)) =
                        LOWER(TRIM(purchases.farmer_name))
              ) = 1
        """)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# --------------------------------------------------
# VALIDATION AND CROP HELPERS
# --------------------------------------------------

def valid_phone(phone):
    digits = re.sub(r"[\s-]", "", phone or "")

    if digits.startswith("+91"):
        digits = digits[3:]

    return bool(re.fullmatch(r"[6-9]\d{9}", digits))


def parse_non_negative_number(value):
    number = float(value)

    if not math.isfinite(number) or number < 0:
        raise ValueError

    return number


def get_owned_crop(conn, crop_id):
    if g.user is None:
        return None

    return conn.execute("""
        SELECT *
        FROM farmer_crops
        WHERE id = ? AND owner_user_id = ?
    """, (crop_id, g.user["id"])).fetchone()


# --------------------------------------------------
# LOAD LOGGED-IN USER
# --------------------------------------------------

@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = None

    if user_id is not None:
        conn = get_db()

        try:
            g.user = conn.execute("""
                SELECT id, farmer_name, username
                FROM users
                WHERE id = ?
            """, (user_id,)).fetchone()
        finally:
            conn.close()

        if g.user is None:
            session.clear()


# --------------------------------------------------
# LOGIN REQUIRED DECORATOR
# --------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            flash("Please log in to access that page.", "error")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        return redirect(url_for("home"))

    if request.method == "POST":
        farmer_name = request.form.get("farmer_name", "").strip().upper()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not farmer_name or not username or not password:
            flash("Please fill in all fields.", "error")
            return render_template("register.html")

        if len(farmer_name) > 80:
            flash("Farmer name must not exceed 80 characters.", "error")
            return render_template("register.html")

        if not re.fullmatch(r"[A-Za-z0-9_]{4,30}", username):
            flash(
                "Username must be 4-30 characters using letters, "
                "numbers, or underscores.",
                "error"
            )
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)
        conn = get_db()

        try:
            conn.execute("""
                INSERT INTO users (farmer_name, username, password_hash)
                VALUES (?, ?, ?)
            """, (farmer_name, username, password_hash))
            conn.commit()

        except sqlite3.IntegrityError:
            conn.rollback()
            flash(
                "That username is already registered. Please choose another.",
                "error"
            )
            return render_template("register.html")

        finally:
            conn.close()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        try:
            user = conn.execute("""
                SELECT *
                FROM users
                WHERE username = ? COLLATE NOCASE
            """, (username,)).fetchone()
        finally:
            conn.close()

        if user is None or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("home"))

    return render_template("login.html")


# --------------------------------------------------
# HOME AND CROP SEARCH
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def home():
    results = []
    crop_name = ""
    message = ""

    conn = get_db()

    try:
        farmer_crops = conn.execute("""
            SELECT *
            FROM farmer_crops
            ORDER BY id DESC
        """).fetchall()

        if request.method == "POST":
            crop_name = request.form.get("crop", "").strip()

            if not crop_name:
                message = "Please enter a crop name."
            else:
                results = conn.execute("""
                    SELECT *
                    FROM farmer_crops
                    WHERE LOWER(TRIM(crop)) = LOWER(TRIM(?))
                    ORDER BY id DESC
                """, (crop_name,)).fetchall()

                if not results:
                    message = (
                        f"No registered crop found for '{crop_name}'. "
                        "Please register the crop first."
                    )

        available_crops = farmer_crops

    finally:
        conn.close()

    return render_template(
        "index.html",
        results=results,
        crop_name=crop_name,
        message=message,
        farmer_crops=farmer_crops,
        available_crops=available_crops,
        user=g.user
    )


# --------------------------------------------------
# ADD FARMER CROP
# --------------------------------------------------

@app.route("/add-crop", methods=["POST"])
@login_required
def add_crop():
    crop = request.form.get("new_crop", "").strip()
    quantity_text = request.form.get("quantity", "").strip()
    location = request.form.get("location", "").strip()
    market_name = request.form.get("market_name", "").strip()
    price_text = request.form.get("expected_price", "").strip()
    phone_number = request.form.get("phone_number", "").strip()

    if not all([
        crop, quantity_text, location,
        market_name, price_text, phone_number
    ]):
        flash("Please fill in all crop details.", "error")
        return redirect(url_for("home"))

    if (
        len(crop) > 80
        or len(location) > 120
        or len(market_name) > 120
    ):
        flash(
            "Please check the length of crop, location or market name.",
            "error"
        )
        return redirect(url_for("home"))

    if not valid_phone(phone_number):
        flash("Enter a valid 10-digit Indian mobile number.", "error")
        return redirect(url_for("home"))

    try:
        quantity = parse_non_negative_number(quantity_text)
        expected_price = parse_non_negative_number(price_text)

        if quantity <= 0:
            raise ValueError
    except ValueError:
        flash(
            "Enter a valid quantity greater than 0 and a valid price.",
            "error"
        )
        return redirect(url_for("home"))

    conn = get_db()

    try:
        conn.execute("""
            INSERT INTO farmer_crops (
                farmer_name, crop, quantity, location,
                expected_price, phone_number, market_name, owner_user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            g.user["farmer_name"].strip().upper(),
            crop,
            quantity,
            location,
            expected_price,
            phone_number,
            market_name,
            g.user["id"]
        ))
        conn.commit()

    except sqlite3.Error:
        conn.rollback()
        flash("Unable to save crop details. Please try again.", "error")
        return redirect(url_for("home"))

    finally:
        conn.close()

    flash("Crop details saved successfully!", "success")
    return redirect(url_for("home"))


# --------------------------------------------------
# DELETE CROP
# --------------------------------------------------

@app.route("/delete-crop/<int:crop_id>", methods=["POST"])
@login_required
def delete_crop(crop_id):
    conn = get_db()

    try:
        result = conn.execute("""
            DELETE FROM farmer_crops
            WHERE id = ? AND owner_user_id = ?
        """, (crop_id, g.user["id"]))
        conn.commit()

        if result.rowcount == 0:
            flash("Crop not found or you cannot delete this crop.", "error")
        else:
            flash("Crop deleted successfully!", "success")

    finally:
        conn.close()

    return redirect(url_for("home"))


# --------------------------------------------------
# EDIT CROP
# --------------------------------------------------

@app.route("/edit-crop/<int:crop_id>", methods=["GET", "POST"])
@login_required
def edit_crop(crop_id):
    conn = get_db()

    try:
        crop = get_owned_crop(conn, crop_id)

        if crop is None:
            flash("Crop not found or access denied.", "error")
            return redirect(url_for("home"))

        if request.method == "POST":
            new_crop = request.form.get("crop", "").strip()
            quantity_text = request.form.get("quantity", "").strip()
            location = request.form.get("location", "").strip()
            price_text = request.form.get("expected_price", "").strip()
            phone_number = request.form.get("phone_number", "").strip()
            market_name = request.form.get("market_name", "").strip()

            if not all([
                new_crop, quantity_text, location,
                price_text, phone_number, market_name
            ]):
                flash("Please fill in all fields.", "error")
                return redirect(url_for("edit_crop", crop_id=crop_id))

            if (
                len(new_crop) > 80
                or len(location) > 120
                or len(market_name) > 120
            ):
                flash(
                    "Please check the length of the entered details.",
                    "error"
                )
                return redirect(url_for("edit_crop", crop_id=crop_id))

            if not valid_phone(phone_number):
                flash("Enter a valid 10-digit phone number.", "error")
                return redirect(url_for("edit_crop", crop_id=crop_id))

            try:
                quantity = parse_non_negative_number(quantity_text)
                price = parse_non_negative_number(price_text)

                if quantity <= 0:
                    raise ValueError
            except ValueError:
                flash("Enter valid quantity and price.", "error")
                return redirect(url_for("edit_crop", crop_id=crop_id))

            conn.execute("""
                UPDATE farmer_crops
                SET crop = ?, quantity = ?, location = ?,
                    expected_price = ?, phone_number = ?, market_name = ?
                WHERE id = ? AND owner_user_id = ?
            """, (
                new_crop,
                quantity,
                location,
                price,
                phone_number,
                market_name,
                crop_id,
                g.user["id"]
            ))
            conn.commit()
            flash("Crop updated successfully!", "success")
            return redirect(url_for("home"))

        return render_template("edit_crop.html", crop=crop)

    finally:
        conn.close()


# --------------------------------------------------
# STOCK DETAILS
# --------------------------------------------------

@app.route("/stock-details")
@login_required
def stock_details():
    conn = get_db()

    try:
        crops = conn.execute("""
            SELECT id, crop, quantity, location,
                   expected_price, market_name
            FROM farmer_crops
            WHERE owner_user_id = ?
            ORDER BY id DESC
        """, (g.user["id"],)).fetchall()
    finally:
        conn.close()

    return render_template("stock_details.html", crops=crops)


# --------------------------------------------------
# CUSTOMER BUY NOW
# --------------------------------------------------

@app.route("/buy-now/<int:crop_id>", methods=["POST"])
def buy_now(crop_id):
    customer_name = request.form.get("customer_name", "").strip()
    customer_phone = request.form.get("customer_phone", "").strip()
    quantity_text = request.form.get("quantity", "").strip()

    if not customer_name or len(customer_name) > 80:
        flash("Enter a valid customer name.", "error")
        return redirect(url_for("home"))

    if not valid_phone(customer_phone):
        flash("Enter a valid 10-digit mobile number.", "error")
        return redirect(url_for("home"))

    try:
        quantity = parse_non_negative_number(quantity_text)
        if quantity <= 0:
            raise ValueError
    except ValueError:
        flash("Enter a valid quantity greater than zero.", "error")
        return redirect(url_for("home"))

    conn = get_db()

    try:
        # Lock the SQLite write transaction while checking and reducing stock.
        conn.execute("BEGIN IMMEDIATE")

        crop = conn.execute("""
            SELECT *
            FROM farmer_crops
            WHERE id = ?
        """, (crop_id,)).fetchone()

        if crop is None:
            conn.rollback()
            flash("Crop not found.", "error")
            return redirect(url_for("home"))

        if quantity > crop["quantity"]:
            conn.rollback()
            flash(
                f"Only {crop['quantity']} kg stock is available.",
                "error"
            )
            return redirect(url_for("home"))

        total_amount = quantity * crop["expected_price"]

        conn.execute("""
            UPDATE farmer_crops
            SET quantity = quantity - ?
            WHERE id = ? AND quantity >= ?
        """, (quantity, crop_id, quantity))

        if conn.execute("SELECT changes()").fetchone()[0] != 1:
            conn.rollback()
            flash("Stock is no longer available. Try again.", "error")
            return redirect(url_for("home"))

        conn.execute("""
            INSERT INTO purchases (
                crop_id, crop_name, farmer_name,
                customer_name, customer_phone,
                quantity, price_per_kg, total_amount,
                owner_user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            crop_id,
            crop["crop"],
            crop["farmer_name"],
            customer_name,
            customer_phone,
            quantity,
            crop["expected_price"],
            total_amount,
            crop["owner_user_id"]
        ))

        conn.commit()
        flash(
            f"Purchase successful! Total amount: ₹{total_amount:.2f}",
            "success"
        )

    except sqlite3.Error:
        conn.rollback()
        flash("Purchase failed. Please try again.", "error")

    finally:
        conn.close()

    return redirect(url_for("home"))


# --------------------------------------------------
# PURCHASE HISTORY
# --------------------------------------------------

@app.route("/purchase-history")
@login_required
def purchase_history():
    conn = get_db()

    try:
        purchases = conn.execute("""
            SELECT *
            FROM purchases
            WHERE owner_user_id = ?
            ORDER BY id DESC
        """, (g.user["id"],)).fetchall()
    finally:
        conn.close()

    return render_template(
        "purchase_history.html",
        purchases=purchases
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

init_db()

if __name__ == "__main__":
    app.run(debug=False)
