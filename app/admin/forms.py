from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, EqualTo

from app.models import Admin, Tag, Role, Auth


class LoginForm(FlaskForm):
    """管理员登录表单"""
    account = StringField(
        label="账号",
        validators=[DataRequired("请输入账号")],
        description="账号",
        render_kw={"class": "form-control", "placeholder": "请输入账号！", }
    )

    pwd = PasswordField(
        label="密码",
        validators=[DataRequired("请输入密码")],
        description="密码",
        render_kw={"class": "form-control", "placeholder": "请输入密码！", }
    )

    submit = SubmitField(
        '登录',
        render_kw={"class": "btn btn-primary btn-block btn-flat"}
    )

    def validate_account(self, field):
        account = field.data
        admin = Admin.query.filter_by(name=account).count()
        if admin == 0:
            raise ValidationError("账号不存在")


class TagForm(FlaskForm):
    """标签表单"""
    name = StringField(
        label="名称",
        validators=[DataRequired("请输入标签")],
        description="标签",
        render_kw={"class": "form-control", "placeholder": "请输入标签", "id": "input_name"}
    )

    submit = SubmitField('编辑/添加', render_kw={"class": "btn btn-primary"})


class MovieForm(FlaskForm):
    """电影表单"""
    title = StringField(
        label="片名",
        validators=[DataRequired("请输入片名")],
        description="标签",
        render_kw={"class": "form-control", "placeholder": "请输入电影名", "id": "input_title"
                   })

    url = FileField(
        label="文件",
        validators=[DataRequired("请上传文件")],
        description="文件"
    )

    info = TextAreaField(
        label="简介",
        validators=[DataRequired("请输入简介")],
        description="标签",
        render_kw={"class": "form-control", "rows": 10, "placeholder": "请输入简介"})

    logo = FileField(
        label="封面",
        validators=[DataRequired("请上传封面")],
        description="封面"
    )

    star = SelectField(
        label="星级",
        validators=[DataRequired("请选择星际")],
        description="星级",
        coerce=int,
        choices=[(1, "1星"), (2, "2星"), (3, "3星"), (4, "4星"), (5, "5星")],
        render_kw={"class": "form-control"})

    tag_id = SelectField(
        label="标签",
        # validators=[DataRequired("请选择标签")],
        # description="标签",
        coerce=int,
        render_kw={"class": "form-control"}
    )

    area = StringField(
        label="地区",
        validators=[DataRequired("请输入地区")],
        description="地区",
        render_kw={"class": "form-control", "placeholder": "请输入地区"})

    length = StringField(
        label="片长",
        validators=[DataRequired("请输入片长")],
        description="片长",
        render_kw={"class": "form-control", "placeholder": "请输入片长"})

    release_time = StringField(
        label="上映时间",
        validators=[DataRequired("请输入上映时间")],
        description="上映时间",
        render_kw={"class": "form-control", "placeholder": "上映时间", "id": "input_release_time"})

    submit = SubmitField('编辑/添加', render_kw={"class": "btn btn-primary"})

    def __init__(self, *args, **kwargs):
        super(MovieForm, self).__init__(*args, **kwargs)
        self.tag_id.choices = [(v.id, v.name) for v in Tag.query.all()]


class PreviewForm(FlaskForm):
    title = StringField(label="预告标题", validators=[DataRequired("请输入预告片名")], description="预告片名",
                        render_kw={"class": "form-control", "placeholder": "请输入预告片名", "id": "input_title"})
    logo = FileField(label="预告封面", validators=[DataRequired("请上传预告封面")], description="预告封面")
    submit = SubmitField('编辑/添加', render_kw={"class": "btn btn-primary"})


class PwdForm(FlaskForm):
    old_pwd = PasswordField(
        label="旧密码",
        validators=[DataRequired("请输入旧密码")],
        description="密码",
        render_kw={"class": "form-control", "placeholder": "请输入旧密码！", }
    )

    new_pwd = PasswordField(
        label="新密码",
        validators=[DataRequired("请输入新密码")],
        description="密码",
        render_kw={"class": "form-control", "placeholder": "请输入新密码！", }
    )

    submit = SubmitField('确认', render_kw={"class": "btn btn-primary"})

    def validate_old_pwd(self, field):
        from flask import session
        pwd = field.data
        name = session["admin"]
        print(name)
        admin = Admin.query.filter_by(
            name=name
        ).first()
        if not admin.check_pwd(pwd):
            raise ValidationError("密码不正确")


class AuthForm(FlaskForm):
    name = StringField(
        label="权限名称",
        validators=[DataRequired("请输入权限名称")],
        description="权限名称",
        render_kw={"class": "form-control", }
    )
    url = StringField(
        label="权限地址",
        validators=[DataRequired("请输入权限地址")],
        description="权限地址",
        render_kw={"class": "form-control", }
    )

    submit = SubmitField(
        '添加',
        render_kw={"class": "btn btn-primary btn-block btn-flat"}
    )


class AdminForm(FlaskForm):
    """管理员表单"""
    name = StringField(
        label="账号",
        validators=[DataRequired("请输入账号")],
        description="账号",
        render_kw={"class": "form-control", "placeholder": "请输入账号！", }
    )

    pwd = PasswordField(
        label="密码",
        validators=[DataRequired("请输入密码")],
        description="密码",
        render_kw={"class": "form-control", "placeholder": "请输入密码！", }
    )

    re_pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请再次输入密码"),
            EqualTo('pwd', message="两次密码不一致！")
        ],
        description="密码",
        render_kw={"class": "form-control", "placeholder": "请再次输入密码！", }
    )

    role_id = SelectField(
        label="角色",
        # validators=[DataRequired("请选择标签")],
        # description="标签",
        coerce=int,
        render_kw={"class": "form-control"}
    )

    submit = SubmitField(
        '添加',
        render_kw={"class": "btn btn-primary"}
    )

    def __init__(self, *args, **kwargs):
        super(AdminForm, self).__init__(*args, **kwargs)
        self.role_id.choices = [(v.id, v.name) for v in Role.query.all()]


class RoleForm(FlaskForm):
    """角色表单"""
    name = StringField(
        label="角色名称",
        validators=[DataRequired("请输入角色名称")],
        description="角色名称",
        render_kw={"class": "form-control", }
    )
    auths = SelectMultipleField(
        label="权限列表",
        validators=[DataRequired("请选择权限列表")],
        coerce=int,
        description="权限列表",
        render_kw={
            "class":"form-control"
        }
    )

    submit = SubmitField(
        '添加',
        render_kw={"class": "btn btn-primary"}
    )

    def __init__(self, *args, **kwargs):
        super(RoleForm, self).__init__(*args, **kwargs)
        self.auths.choices = [(v.id, v.name) for v in Auth.query.all()]