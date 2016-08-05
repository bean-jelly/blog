from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User

class NameForm(Form):
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')

class LoginForm(Form):
    email = StringField('邮箱', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('密码', validators=[Required()])
    remember_me = BooleanField('免登录')
    submit = SubmitField('登录')

class RegistrationForm(Form):
    email = StringField('邮箱', validators=[Required(), Length(1, 64), Email()])
    username = StringField('用户名', validators=[Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('密码', validators=[Required(), EqualTo('password2', message='密码必须一致')])
    password2 = PasswordField('再次确认', validators=[Required()])
    submit = SubmitField('注册')

    #如果表单类中定义了validate_开头切后面跟着字段名的方法，这个方法就和常规的验证函数一起调用。
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            #自定义的验证函数想要表示验证失败，可以抛出ValidationError异常，其参数就是错误消息
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username = field.data).first():
            raise ValidationError('username already registered.')

class ChangePasswordForm(Form):
    oldPassword = PasswordField('旧密码',validators=[Required()])
    newPassword = PasswordField('新密码', validators=[Required(), EqualTo('newPassword2',message='新密码必须一致')])
    newPassword2 = PasswordField('再次确认', validators=[Required()])
    submit = SubmitField('修改')

class ChangeEmailForm(Form):
    email = StringField('新的邮箱', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('密码', validators=[Required()])
    submit = SubmitField('更新邮箱')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('邮箱已被注册')