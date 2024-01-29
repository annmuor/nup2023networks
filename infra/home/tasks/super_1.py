from flask import Flask
app = Flask(__name__)

@app.route("/")
def hello():
    return "Gunicorn says: Go to /admin/flag for FLAG"

@app.route("/admin/flag")
def flag():
    return "Gunicorn says: flag = NUP23{R3qu1st_sm4gl1ng_1s_f4n}"

