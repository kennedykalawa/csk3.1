from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "This is may first flask server"


app.route("/to_python")
