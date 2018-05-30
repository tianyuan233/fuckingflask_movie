from uuid import uuid4

from flask import render_template, redirect, url_for, flash, session, request
from werkzeug.security import generate_password_hash

from app import db
from app.home.forms import RegisterForm, LoginForm
from app.models import User, Userlog
from . import home


@home.route("/")
def index():
    return render_template('home/index.html')


@home.route("/login/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=data["name"]).first()
        if not user.check_pwd(data["pwd"]):
            flash("密码错误", "error")
            return redirect(url_for("home.login"))
        session["user"] = data["name"]
        session["user_id"] = user.id

        userlog = Userlog(
            user_id=user.id,
            ip=request.remote_addr,
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for("home.index"))
    return render_template('home/login.html', form=form)


@home.route("/logout/")
def logout():
    return redirect(url_for("home.login"))


@home.route("/register/", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        data = form.data
        user = User(
            name=data["name"],
            email=data["email"],
            phone=data["phone"],
            pwd=generate_password_hash(data["pwd"]),
            uuid=uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash("注册成功", "ok")

    return render_template('home/register.html', form=form)


@home.route("/user/")
def user():
    return render_template('home/user.html')


@home.route("/pwd/")
def pwd():
    return render_template('home/pwd.html')


@home.route("/comments/")
def comments():
    return render_template('home/comments.html')


@home.route("/loginlog/")
def loginlog():
    return render_template('home/loginlog.html')


@home.route("/moviecol/")
def moviecol():
    return render_template('home/moviecol.html')


# @home.route("/")
# def index():
#     return render_template('home/index.html')

@home.route("/animation/")
def animation():
    return render_template('home/animation.html')


@home.route("/search/")
def search():
    return render_template('home/search.html')


@home.route("/play/")
def play():
    return render_template('home/play.html')
