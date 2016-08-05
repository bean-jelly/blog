from . import mail
from flask import current_app, render_template
from threading import Thread
from flask_mail import Message

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

#Flask_Mail中的send()函数使用了current_app，因此必须激活程序上下文。不过，在不同线程中执行mail.send()函数
#时，程序上下文要使用app.app_context()人工创建。

def send_mail(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
