import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
	SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
	SQLALCHEMY_COMMIT_ON_TEARDOWN = True
	SQLALCHEMY_RECORD_QUERIES = True
	FLASKY_MAIL_SUBJECT_PREFIX = '[Flasky]'
	FLASKY_MAIL_SENDER = 'ly7225397@163.com'
	FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN') or '446395776@qq.com'
	SQLALCHEMY_TRACK_MODIFICATIONS = True
	MAIL_USERNAME = 'ly7225397@163.com'
	MAIL_PASSWORD = 'zyh518629'
	MAIL_SERVER = 'smtp.163.com'
	MAIL_PORT = 465
	MAIL_USE_SSL = True
	FLASKY_POSTS_PER_PAGE = 10
	FLASKY_FOLLOWERS_PER_PAGE = 50
	FLASKY_COMMENTS_PER_PAGE = 20
	QINIU_DOMAIN1 = 'http://ob4a4d6kg.bkt.clouddn.com/'
	QINIU_DOMAIN = 'http://ob4tuss43.bkt.clouddn.com/'
	QINIU_BUCKET_NAME = 'newflasky'
	ALLOWED_EXT=set(['png','jpg','bmp','gif'])
	QINIU_ACCESS_KEY = 'xkcdp73Srw5_S29OJhspBIBOIAtC-14UKunmzCf-'
	QINIU_SECRET_KEY = 'CHXX7p_olQUycT9pQOhLih8X03krNyhNvHO51TaP'
	FLASKY_SLOW_DB_QUERY_TIME=0.5

	@staticmethod
	def init_app(app):
		pass

class DevelopmentConfig(Config):
	DEBUG = True
	SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')

class TestingConfig(Config):
	TESTING = True
	SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')

class ProductingConfig(Config):
	SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')

	@classmethod
	def init_app(cls, app):
	    Config.init_app(app)
	    # email errors to the administrators
	    import logging
	    from logging.handlers import SMTPHandler
	    credentials = None
	    secure = None
	    if getattr(cls, 'MAIL_USERNAME', None) is not None:
	        credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
	        if getattr(cls, 'MAIL_USE_TLS', None):
	            secure = ()
	    mail_handler = SMTPHandler(mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),fromaddr=cls.FLASKY_MAIL_SENDER,toaddrs=[cls.FLASKY_ADMIN],subject=cls.FLASKY_MAIL_SUBJECT_PREFIX + ' Application Error',credentials=credentials,secure=secure)
	    mail_handler.setLevel(logging.ERROR)
	    app.logger.addHandler(mail_handler)


config={
	'development': DevelopmentConfig,
	'testing': TestingConfig,
	'production': ProductingConfig,
	'default': DevelopmentConfig
}

if __name__ == '__main__':
	print(os.environ.get('FLASKY_ADMIN'))
