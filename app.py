import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

"""key: export API_KEY=pk_ffc1e44d61c74f3cb44a06c7bad07d8c"""
# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_id = session["user_id"]

    stocks = db.execute(
        "SELECT symbol, name, price, SUM(shares) as totalShares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[
        0]["cash"]

    total = cash

    for stock in stocks:
        total += stock["price"] * stock["totalShares"]

    return render_template("index.html", stocks=stocks, cash=cash, total=total, usd=usd)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)

        if not symbol:
            return apology("Symbol Empty, Please Enter something")
        elif not stock:
            return apology("Symbol does not exist")

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Shares must be a valid number!")

        if shares <= 0:
            return apology("Shares must be a positive number!")

        user_id = session["user_id"]
        cash = db.execute("SEL`ECT cash FROM users WHERE id = ?", user_id)[
            0]["cash"]

        stock_name = stock["name"]
        stock_price = stock["price"]
        total_price = stock_price * shares

        if cash < total_price:
            return apology("Not enough money!")
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       cash - total_price, user_id)
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                       user_id, stock_name, shares, stock_price, 'buy', symbol)

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute(
        "SELECT type, symbol, price, shares, time FROM transactions WHERE user_id = ?", user_id)

    return render_template("history.html", transactions=transactions, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Please enter symbol!")

        stock = lookup(symbol)

        if not stock:
            return apology("Invalid Symbol")

        return render_template("qouted.html", stock=stock, usd=usd)
    else:
        return render_template("qoute.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if (request.method == "POST"):
        """get info entered by user from register page"""
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        """checking if user input is entered and correct"""
        if not username:
            return apology('Username is Required!')
        elif not password:
            return apology('Password Required!')
        elif not confirmation:
            return apology('Please Confirm your password!')

        """check if user password and confirmation password is matching"""
        if password != confirmation:
            return apology('Passwords do not match!')

        """hash the user password so it can stored in the database as hash"""
        hash = generate_password_hash(password)

        try:
            """insert values into our database"""
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?,?)", username, hash)
            return redirect('/')
        except:
            return apology('Username already been registered!')

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if shares <= 0:
            return apology("Shares must be a positive number!")

        stock_price = lookup(symbol)["price"]
        stock_name = lookup(symbol)["name"]
        stock_sold = shares * stock_price

        shares_owned = db.execute("SELECT SUM(shares) FROM transactions WHERE user_id = ? AND symbol = ?",
                                  user_id, symbol)[0]["SUM(shares)"]

        if shares_owned < shares:
            return apology("You dont have enough shares to sell!")

        current_cash = db.execute(
            "SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   current_cash + stock_sold, user_id)

        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, stock_name, -shares, stock_price, "sell", symbol)
        return redirect("/")

    else:
        symbols = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
        return render_template("sell.html", symbols=symbols)


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """Add more cash to balance"""
    user_id = session["user_id"]
    if request.method == "POST":
        deposit = int(request.form.get("deposit"))

        if deposit <= 0:
            return apology("Deposit Failed, Enter valid Number")

        current_balance = db.execute(
            "SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   current_balance + deposit, user_id)

        return redirect("/")

    else:
        return render_template("deposit.html")
