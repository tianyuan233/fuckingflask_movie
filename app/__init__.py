from flask import Flask
from flask import render_template
from flask_sqlalchemy import SQLAlchemy
import os
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:1234567@localhost:3306/movie"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SECRET_KEY"] = "asdqwezxczxc"
app.config["UP_DIR"] = os.path.join(os.path.dirname(os.path.abspath(__file__)),'static/uploadsfiles/')
app.debug = True

db = SQLAlchemy(app)

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix="/admin")


@app.errorhandler(404)
def page_not_found(error):
    return render_template("home/404.html"), 404
