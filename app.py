import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd
app.jinja_env.globals.update(usd=usd)

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
    id = session["user_id"]
    stocks = db.execute("SELECT * FROM stocks WHERE user_id == ?", id)
    users = db.execute("SELECT * FROM users WHERE id == ?", id)[0]
    total = 0
    for stock in stocks:
        symbol = lookup(stock["stock_symbol"])
        total += symbol["price"] * stock["total_shares"]
    return render_template("index.html", users=users, stocks=stocks, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Please Enter a Stock Symbol", 400)
        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("Stock Not Found", 400)
        else:
            shares = request.form.get("shares")
            if not shares.isnumeric() or int(shares) < 0:
                return apology("Invalid Number Of Stocks", 400)
            else:
                shares = int(shares)
            share_price = int(symbol["price"])
            price = share_price * shares
            id = session["user_id"]
            cash = db.execute("SELECT cash FROM users WHERE id == ?", id)[0]["cash"]
            if cash < price:
                return apology("Not Enough Cash", 400)
            else:
                cash -= price
                db.execute("UPDATE users SET cash = ? WHERE id == ?", cash, id)
                db.execute("INSERT INTO transactions (transaction_type, user_id, stock_symbol, stock_name, shares, price) VALUES (?,?,?,?,?,?)",
                           1, id, symbol["symbol"], symbol["name"], shares, share_price)
                user_stocks = db.execute("SELECT * FROM stocks WHERE stock_symbol == ? AND user_id == ?;", symbol["symbol"], id)
                if len(user_stocks) == 0:
                    db.execute("INSERT INTO stocks (user_id, stock_symbol, stock_name, total_shares, price) VALUES (?, ?, ?, ?, ?)",
                               id, symbol["symbol"], symbol["name"], shares, symbol["price"], )
                elif len(user_stocks) == 1:
                    new_shares = user_stocks[0]["total_shares"] + shares
                    db.execute("UPDATE stocks SET total_shares = ?, price = ? WHERE user_id == ? AND stock_symbol == ?",
                               new_shares, price, id, symbol["symbol"])
                return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    id = session["user_id"]
    transactions = db.execute("SELECT * FROM transactions WHERE user_id == ?", id)
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("Stock Not Found", 400)
        else:
            return render_template("quoted.html", symbol=symbol)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # no session.clear ->see what happens when you register multiple times
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must re-enter password", 400)
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 0 or request.form.get("password") != request.form.get("confirmation"):
            return apology("invalid username/password do not match", 400)
        hash_password = generate_password_hash(request.form.get("password"))
        id = db.execute("INSERT INTO users (username, hash) VALUES (?, ?);", request.form.get("username"), hash_password)
        session["user_id"] = id
        return redirect("/")

    # """Register user"""
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    id = session["user_id"]
    if request.method == "POST":
        symbol = lookup(request.form.get("symbol"))
        amount = int(request.form.get("shares"))
        if symbol == None or amount == None:
            return apology("No Stock Selected/No Amount Entered", 402)
        else:
            stock = db.execute("SELECT * FROM stocks WHERE user_id == ? AND stock_symbol == ?", id, symbol["symbol"])
            if len(stock) == 1:
                if amount > stock[0]["total_shares"]:
                    return apology("Not Enough Stocks", 400)
                else:
                    db.execute("INSERT INTO transactions (transaction_type, user_id, stock_symbol, stock_name, shares, price) VALUES (?, ?, ?, ?, ?, ?)",
                               2, id, symbol["symbol"], symbol["name"], amount, symbol["price"])
                    new_shares = stock[0]["total_shares"] - amount
                    if new_shares != 0:
                        db.execute("UPDATE stocks SET total_shares = ?, price= ? WHERE user_id == ? AND stock_symbol == ?",
                                   new_shares, symbol["price"], id, symbol["symbol"])
                    else:
                        db.execute("Delete FROM stocks WHERE user_id == ? AND stock_symbol == ?", id, symbol["symbol"])
                    return redirect("/")
            else:
                return apology("Stock Not Found", 404)
    else:
        id = session["user_id"]
        stocks = db.execute("SELECT * FROM stocks WHERE user_id == ?", id)
        return render_template("sell.html", stocks=stocks)


@app.route("/addcash", methods=["GET", "POST"])
@login_required
def addcash():
    if request.method == "POST":
        id = session["user_id"]
        cash_to_add = float(request.form.get("add"))
        current_cash = db.execute("SELECT cash FROM users WHERE id == ?",  id)[0]["cash"]
        db.execute("Update users SET cash = ? WHERE id = ?", cash_to_add + current_cash, id)
        return redirect("/")
    else:
        return redirect("/")