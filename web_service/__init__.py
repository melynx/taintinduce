import os

from flask import Flask, g


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(SECRET_KEY='dev', WORKER_URL='http://localhost:12345')

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    app.config['EXPLAIN_TEMPLATE_LOADING'] = True

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from . import auth
    app.register_blueprint(auth.bp)

    from . import taintinduce
    app.register_blueprint(taintinduce.bp)
    app.add_url_rule('/', endpoint='index')

    return app

