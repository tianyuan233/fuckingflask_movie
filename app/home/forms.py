from flask_wtf import FlaskForm
from wtforms.fields import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email, Regexp, ValidationError

from app.models import User


class RegisterForm(FlaskForm):
    name = StringField(
        label="账号",
        validators=[DataRequired("请输入账号")],
        description="账号",
        render_kw={"class": "form-control input-lg", "placeholder": "请输入账号！", }
    )

    pwd = PasswordField(
        label="密码",
        validators=[DataRequired("请输入密码")],
        description="密码",
        render_kw={"class": "form-control input-lg", "placeholder": "请输入密码！", }
    )

    re_pwd = PasswordField(
        label="重复密码",
        validators=[
            DataRequired("请再次输入密码"),
            EqualTo('pwd', message="两次密码不一致！")
        ],
        description="重复密码",
        render_kw={"class": "form-control input-lg", "placeholder": "请再次输入密码！", }
    )

    email = StringField(
        label="邮箱",
        validators=[DataRequired("请输入邮箱"),
                    Email("邮箱格式不正确")],
        description="email",
        render_kw={"class": "form-control input-lg", "placeholder": "请输入邮箱！", }
    )
    phone = StringField(
        label="手机号",
        validators=[DataRequired("请输入手机号"),
                    Regexp("1\d{10}", message="手机号码格式不正确")],
        description="email",
        render_kw={"class": "form-control input-lg", "placeholder": "请输入邮箱！", }

    )

    submit = SubmitField(
        label="注册",
        render_kw={"class": "btn btn-lg btn-success btn-block"}
    )

    def validate_name(self, field):
        print("自定义验证函数-name")
        name = field.data
        print(name)
        user = User.query.filter_by(name=name).count()
        if user == 1:
            raise ValidationError("昵称已存在")

    def validate_phone(self, field):
        print("自定义验证函数-phone")
        phone = field.data
        print(phone)
        user = User.query.filter_by(phone=phone).count()
        if user == 1:
            raise ValidationError("手机号已存在")

    def validate_email(self, field):
        print("自定义验证函数-email")
        email = field.data
        print(email)
        user = User.query.filter_by(email=email).count()
        if user == 1:
            raise ValidationError("邮箱已存在")


class LoginForm(FlaskForm):
    """用户登录表单"""
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

    submit = SubmitField(
        '登录',
        render_kw={"class": "btn btn-primary btn-block btn-flat"}
    )

    def validate_name(self, field):
        name = field.data
        admin = User.query.filter_by(name=name).count()
        if admin == 0:
            raise ValidationError("账号不存在")
