import datetime
import os
import uuid
from uuid import uuid4

from flask import render_template, redirect, url_for, flash, session, request
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app import db, app
from app.home.forms import RegisterForm, LoginForm, UserdetailForm, PwdForm
from app.models import User, Userlog, Comment, Moviecol, Movie
from . import home


# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


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
        session["user"] = user.name
        session["user_id"] = user.id

        userlog = Userlog(
            user_id=user.id,
            ip=request.remote_addr,
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for("home.index"))
    return render_template('home/login.html', form=form)

#退出
@home.route("/logout/")
def logout():
    return redirect(url_for("home.login"))

#注册
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

#用户页
@home.route("/user/", methods=["GET", "POST"])
def user():
    form = UserdetailForm()
    user = User.query.get(int(session["user_id"]))
    form.face.validators = []
    if request.method == "GET":
        # 赋初值
        form.name.data = user.name
        form.email.data = user.email
        form.phone.data = user.phone
        form.info.data = user.info
    if form.validate_on_submit():
        data = form.data
        if form.face.data != "":
            file_face = secure_filename(form.face.data.filename)
            if not os.path.exists(app.config["FC_DIR"]):
                os.makedirs(app.config["FC_DIR"])
                os.chmod(app.config["FC_DIR"])
            user.face = change_filename(file_face)
            form.face.data.save(app.config["FC_DIR"] + user.face)

        name_count = User.query.filter_by(name=data["name"]).count()
        if data["name"] != user.name and name_count == 1:
            flash("昵称已经存在!", "error")
            return redirect(url_for("home.user"))

        email_count = User.query.filter_by(email=data["email"]).count()
        if data["email"] != user.email and email_count == 1:
            flash("邮箱已经存在!", "error")
            return redirect(url_for("home.user"))

        phone_count = User.query.filter_by(phone=data["phone"]).count()
        if data["phone"] != user.phone and phone_count == 1:
            flash("手机已经存在!", "error")
            return redirect(url_for("home.user"))

        # 保存
        user.name = data["name"]
        user.email = data["email"]
        user.phone = data["phone"]
        user.info = data["info"]
        db.session.add(user)
        db.session.commit()
        flash("修改成功!", "ok")
        return redirect(url_for("home.user"))
    return render_template("home/user.html", form=form, user=user)

#修改密码
@home.route("/pwd/",methods=["GET","POST"])
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=session["user"]).first()
        from werkzeug.security import generate_password_hash
        user.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(user)
        db.session.commit()
        flash("已成功修改密码", "ok")
        return redirect(url_for("home.pwd"))
    return render_template('home/pwd.html',form=form)


@home.route("/comments/<int:page>",methods=["GET"])
def comments(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template('home/comments.html',page_data=page_data)


@home.route("/loginlog/<int:page>/",methods=["GET"])
def loginlog(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.filter_by(
        user_id=int(session["user_id"])
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    for v in page_data.items:
        print(v)
    return render_template('home/loginlog.html',page_data=page_data)


@home.route("/moviecol/<int:page>",methods=["GET"])
def moviecol(page=None):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(
        Movie
    ).join(
        User
    ).filter(
        Moviecol.user_id == User.id,
        Moviecol.movie_id == Movie.id
    ).order_by(
        Moviecol.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template('home/moviecol.html',page_data=page_data)


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
