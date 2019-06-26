from flask import current_app, g
from flask.cli import with_appcontext

import pyjsonrpc

def get_worker():
    if 'worker' not in g:
        worker_url = current_app.config['WORKER_URL']
        g.worker = pyjsonrpc.HttpClient(url=worker_url)
    return g.worker
