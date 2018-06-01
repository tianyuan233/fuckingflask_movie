import datetime
import os
import uuid
from functools import wraps

from flask import render_template, redirect, url_for, flash, session, request, abort
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app import db, app, login_manager
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AdminForm, AuthForm, RoleForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol, Oplog, Userlog, Adminlog, Role, Auth
from . import admin

@login_manager.user_loader
def load_user(id):
    return Admin.query.get(int(id))

# 上下文处理器
@admin.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data


# 登录验证装饰器
# def admin_login_req(f):
#     @wraps(f)
#     def defcorated_function(*args, **kwargs):
#         if "admin" not in session:
#             return redirect(url_for("admin.login", next=request.url))
#         return f(*args, **kwargs)
#
#     return defcorated_function


# 权限控制装饰器
def admin_auth(f):
    @wraps(f)
    def defcorated_function(*args, **kwargs):
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id,
            Admin.id == session["admin_id"]
        ).first()
        auths = admin.role.auths
        auths = list(map(lambda v: int(v), auths.split(",")))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for val in auths if val == v.id]
        rule = str(request.url_rule)
        print(urls)
        print(rule)
        if rule not in urls:
            abort(404)
        return f(*args, **kwargs)

    return defcorated_function


# 修改文件名称
def change_file(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


@admin.route("/")
def index():
    return render_template("admin/index.html")


@admin.route("/login/", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data["account"]).first()
        if admin and admin.verify_password(data["pwd"]):
            login_user(admin)
            adminlog = Adminlog(
                admin_id=admin.id,
                ip=request.remote_addr,
            )
            db.session.add(adminlog)
            db.session.commit()
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("admin/login.html", form=form)


@admin.route("/logout/")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for("admin.login"))


# 修改密码

@admin.route("/pwd/", methods=['GET', 'POST'])
@login_required
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session["admin"]).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(admin)
        db.session.commit()
        flash("已成功修改密码", "ok")
        return redirect(url_for("admin.pwd"))
    return render_template("admin/pwd.html", form=form)


@admin.route("/tag/add/", methods=['GET', 'POST'])
@admin_auth
def tag_add():
    print(request.url_rule)
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data["name"]).count()
        if tag == 1:
            flash("该标签已存在", "error")
            return redirect(url_for("admin.tag_add"))
        tag = Tag(
            name=data["name"]
        )
        db.session.add(tag)
        db.session.commit()
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="添加标签 %s" % data["name"]
        )
        db.session.add(oplog)
        db.session.commit()
        flash("已成功添加标签", "ok")
        return redirect(url_for("admin.tag_add"))
    return render_template("admin/tag_add.html", form=form)


# 标签列表
@admin.route("/tag/list/<int:page>/", methods=["GET"])
def tag_list(page):
    if page is None:
        page = 1
    page_data = Tag.query.order_by(
        Tag.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/tag_list.html", page_data=page_data)


# 标签删除
@admin.route("/tag/del/<int:id>/", methods=["GET"])
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    oplog = Oplog(
        admin_id=session["admin_id"],
        ip=request.remote_addr,
        reason="删除标签 %s" % tag.name
    )
    db.session.add(oplog)
    db.session.commit()
    flash("已成功删除标签", "ok")
    return redirect(url_for("admin.tag_list", page=1))


# 标签编辑
@admin.route("/tag/edit/<int:id>/", methods=['GET', 'POST'])
def tag_edit(id):
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data["name"]).count()
        if tag_count == 1 and tag.name != data["name"]:
            flash("该标签已存在", "error")
            return redirect(url_for("admin.tag_edit", id=id))
        tag.name = data["name"]
        db.session.add(tag)
        db.session.commit()
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="标签[%s]修改为[%s]" % (tag.name, data["name"])
        )
        db.session.add(oplog)
        db.session.commit()
        flash("已成功修改标签", "ok")
        return redirect(url_for("admin.tag_edit", id=id))
    return render_template("admin/tag_edit.html", form=form, tag=tag)


@admin.route("/movie/add/", methods=['GET', 'POST'])
@admin_auth
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count()
        if movie_count == 1:
            flash("片名已存在", "error")
            return redirect(url_for('admin.movie_add'))
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            # os.chmod(app.config["UP_DIR"], "rw")
        url = change_file(file_url)
        form.url.data.save(app.config["UP_DIR"] + url)
        logo = change_file(file_logo)
        form.logo.data.save(app.config["UP_DIR"] + logo)
        movie = Movie(
            title=data["title"],
            url=url,
            info=data["info"],
            logo=logo,
            star=int(data["star"]),
            playnum=0,
            commentnum=0,
            tag_id=int(data["tag_id"]),
            area=data["area"],
            release_time=data["release_time"],
            length=data["length"]
        )
        db.session.add(movie)
        db.session.commit()
        flash("添加电影成功", "ok")
        return redirect(url_for('admin.movie_add'))
    return render_template("admin/movie_add.html", form=form)


# 电影列表
@admin.route("/movie/list/<int:page>/", methods=["GET", "POST"])
def movie_list(page):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/movie_list.html", page_data=page_data)


# 电影删除
@admin.route("/movie/del/<int:id>/", methods=["GET"])
def movie_del(id=None):
    movie = Movie.query.filter_by(id=id).first_or_404()
    db.session.delete(movie)
    db.session.commit()
    flash("已成功删除电影", "ok")
    return redirect(url_for("admin.movie_list", page=1))


# 电影编辑
@admin.route("/movie/edit/<int:id>/", methods=['GET', 'POST'])
def movie_edit(id):
    form = MovieForm()
    form.url.validators = []
    form.logo.validators = []
    movie = Movie.query.get_or_404(int(id))
    if request.method == "GET":
        form.info.data = movie.info
        form.star.data = movie.star
        form.tag_id.data = movie.tag_id
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count()
        if movie_count == 1 and movie.title != data["title"]:
            flash("片名已存在", "error")
            return redirect(url_for('admin.movie_edit', id=id))

        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])

        if form.url.data != "":
            file_url = secure_filename(form.url.data.filename)
            movie.url = change_file(file_url)
            form.url.data.save(app.config["UP_DIR"] + movie.url)
        if form.logo.data != "":
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_file(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + movie.logo)

        movie.star = data["star"]
        movie.tag_id = data["tag_id"]
        movie.info = data["info"]
        movie.title = data["title"]
        movie.area = data["area"]
        movie.length = data["length"]
        movie.release_time = data["release_time"]

        db.session.add(movie)
        db.session.commit()
        flash("修改电影成功", "ok")
        return redirect(url_for("admin.movie_edit", id=movie.id))
    return render_template("admin/movie_edit.html", form=form, movie=movie)


# 预告添加
@admin.route("/preview/add/", methods=['GET', 'POST'])
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
        logo = change_file(file_logo)
        form.logo.data.save(app.config["UP_DIR"] + logo)
        preview = Preview(
            logo=logo,
            title=data["title"]
        )
        db.session.add(preview)
        db.session.commit()
        flash("修改电影成功", "ok")
        return redirect(url_for("admin.preview_add"))

    return render_template("admin/preview_add.html", form=form)


@admin.route("/preview/list/<int:page>/", methods=['GET'])
def preview_list(page):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(
        Preview.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template("admin/preview_list.html", page_data=page_data)


# 预告删除
@admin.route("/preview/del/<int:id>/", methods=["GET"])
def preview_del(id=None):
    preview = Preview.query.filter_by(id=id).first_or_404()
    db.session.delete(preview)
    db.session.commit()
    flash("已成功删除预告", "ok")
    return redirect(url_for("admin.preview_list", page=1))


# 预告编辑
@admin.route("/preview/edit/<int:id>/", methods=['GET', 'POST'])
def preview_edit(id=None):
    form = PreviewForm()
    form.logo.validators = []
    preview = Preview.query.get_or_404(int(id))
    if request.method == "GET":
        form.title.data = preview.title
    if form.validate_on_submit():
        data = form.data
        preview_count = Preview.query.filter_by(title=data["title"]).count()
        if preview_count == 1 and preview.title != data["title"]:
            flash("预告已存在", "error")
            return redirect(url_for('admin.preview_edit', id=id))
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
        if form.logo.data != "":
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_file(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + preview.logo)
        preview.title = data["title"]

        db.session.add(preview)
        db.session.commit()
        flash("修改预告成功", "ok")
        return redirect(url_for("admin.preview_edit", id=preview.id))
    return render_template("admin/preview_edit.html", form=form, preview=preview)


# 会员列表
@admin.route("/user/list/<int:page>", methods=['GET'])
def user_list(page):
    if page is None:
        page = 1
    page_data = User.query.order_by(
        User.addtime.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/user_list.html", page_data=page_data)


@admin.route("/user/view/<int:id>", methods=['GET'])
def user_view(id=None):
    user = User.query.get_or_404(int(id))
    return render_template("admin/user_view.html", user=user)


@admin.route("/user/del/<int:id>", methods=['GET'])
def user_del(id=None):
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash("删除用户成功", "ok")
    return redirect(url_for("admin.user_list", page=1))


@admin.route("/comment/list/<int:page>/", methods=['GET'])
def comment_list(page):
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
    ).paginate(page=page, per_page=5)
    return render_template("admin/comment_list.html", page_data=page_data)


# 评论删除
@admin.route("/comment/del/<int:id>", methods=['GET'])
def comment_del(id=None):
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash("删除评论成功", "ok")
    return redirect(url_for("admin.comment_list", page=1))


# 收藏列表
@admin.route("/moviecol/list/<int:page>", methods=['GET'])
def moviecol_list(page):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Moviecol.movie_id,
        User.id == Moviecol.user_id
    ).order_by(
        Moviecol.addtime.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/moviecol_list.html", page_data=page_data)


# 删除收藏
@admin.route("/moviecol/del/<int:id>", methods=['GET'])
def moviecol_del(id=None):
    moviecol = Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash("删除收藏成功", "ok")
    return redirect(url_for("admin.moviecol_list", page=1))


# 操作日志
@admin.route("/oplog/list/<int:page>", methods=['GET'])
def oplog_list(page):
    if page == None:
        page = 1
    page_data = Oplog.query.join(
        Admin
    ).filter(
        Admin.id == Oplog.admin_id
    ).order_by(
        Oplog.addtime.desc()
    ).paginate(page=page, per_page=20)

    return render_template("admin/oplog_list.html", page_data=page_data)


# 管理员登陆日志
@admin.route("/adminloginlog/list/<int:page>", methods=['GET'])
def adminloginlog_list(page):
    if page == None:
        page = 1
    page_data = Adminlog.query.join(
        Admin
    ).filter(
        Admin.id == Adminlog.admin_id
    ).order_by(
        Adminlog.addtime.desc()
    ).paginate(page=page, per_page=2)
    return render_template("admin/adminloginlog_list.html", page_data=page_data)


# 用户登陆日志
@admin.route("/userloginlog/list/<int:page>", methods=['GET'])
def userloginlog_list(page):
    if page == None:
        page = 1
    page_data = Userlog.query.join(
        User
    ).filter(
        User.id == Userlog.user_id
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page, per_page=2)
    return render_template("admin/userloginlog_list.html", page_data=page_data)


# 角色添加
@admin.route("/role/add/", methods=["GET", "POST"])
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role.query.filter_by(name=data["name"]).count()
        if role == 1:
            flash("该角色已存在", "error")
            return redirect(url_for("admin.role_add"))
        role = Role(
            name=data["name"],
            auths=",".join(map(lambda v: str(v), data["auths"]))
        )
        db.session.add(role)
        db.session.commit()
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="添加角色 %s" % data["name"]
        )
        db.session.add(oplog)
        db.session.commit()
        flash("已成功添加角色", "ok")
        return redirect(url_for("admin.role_add"))
    return render_template("admin/role_add.html", form=form)


# 角色列表
@admin.route("/role/list/<int:page>", methods=["GET"])
def role_list(page):
    if page is None:
        page = 1
    page_data = Role.query.order_by(
        Role.addtime
    ).paginate(page=page, per_page=5)
    return render_template("admin/role_list.html", page_data=page_data)


# 角色编辑
@admin.route("/role/edit/<int:id>", methods=['GET', 'POST'])
def role_edit(id):
    form = RoleForm()
    role = Role.query.get_or_404(id)
    if request.method == "GET":
        auths = role.auths
        form.auths.data = list(map(lambda v: int(v), auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        role.name = data["name"]
        role.auths = ",".join(map(lambda v: str(v), data["auths"]))
        db.session.add(role)
        db.session.commit()
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="角色[%s]修改为[%s]" % (role.name, data["name"])
        )
        db.session.add(oplog)
        db.session.commit()
        flash("已成功修改角色", "ok")
        return redirect(url_for("admin.role_list", page=1))
    return render_template("admin/role_edit.html", form=form, role=role)


# 角色删除
@admin.route("/role/del/<int:id>")
def role_del(id):
    role = Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    oplog = Oplog(
        admin_id=session["admin_id"],
        ip=request.remote_addr,
        reason="删除角色 %s" % role.name
    )
    db.session.add(oplog)
    db.session.commit()
    flash("已成功删除权限", "ok")
    return redirect(url_for("admin.role_list", page=1))


# 权限添加
@admin.route("/auth/add/", methods=['GET', 'POST'])
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = Auth(
            name=data['name'],
            url=data['url']
        )
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功", "ok")
        return redirect(url_for("admin.auth_add"))
    return render_template("admin/auth_add.html", form=form)


# 权限列表
@admin.route("/auth/list/<int:page>")
def auth_list(page):
    if page is None:
        page = 1
    page_data = Auth.query.order_by(
        Auth.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/auth_list.html", page_data=page_data)


# 权限编辑
@admin.route("/auth/edit/<int:id>", methods=['GET', 'POST'])
def auth_edit(id):
    form = AuthForm()
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth.name = data["name"]
        db.session.add(auth)
        db.session.commit()
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="权限[%s]修改为[%s]" % (auth.url, data["url"])
        )
        db.session.add(oplog)
        db.session.commit()
        flash("已成功修改标签", "ok")
        return redirect(url_for("admin.auth_list", page=1))
    return render_template("admin/auth_edit.html", form=form, auth=auth)


# 权限删除
@admin.route("/auth/del/<int:id>")
def auth_del(id):
    auth = Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    oplog = Oplog(
        admin_id=session["admin_id"],
        ip=request.remote_addr,
        reason="删除权限 %s" % auth.name
    )
    db.session.add(oplog)
    db.session.commit()
    flash("已成功删除权限", "ok")
    return redirect(url_for("admin.auth_list", page=1))


@admin.route("/admin/add/", methods=['GET', 'POST'])
def admin_add():
    form = AdminForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data["name"]).count()
        if admin == 1:
            flash("该角色已存在", "error")
            return redirect(url_for("admin.admin_add"))
        admin = Admin(
            name=data['name'],
            pwd=generate_password_hash(data['pwd']),
            role_id=int(data['role_id']),
            is_super=1
        )
        db.session.add(admin)
        db.session.commit()
        flash("添加管理员成功", "ok")
        return redirect(url_for("admin.admin_add"))
    return render_template("admin/admin_add.html", form=form)


@admin.route("/admin/list/<int:page>", methods=["GET"])
def admin_list(page):
    if page == None:
        page = 1
    page_data = Admin.query.join(Role).filter(
        Role.id == Admin.role_id
    ).order_by(
        Admin.addtime.desc()
    ).paginate(page=page, per_page=5)

    return render_template("admin/admin_list.html", page_data=page_data)


@admin.route("/url", methods=["GET"])
def admin_url():
    a = request.url_rule
    return a
