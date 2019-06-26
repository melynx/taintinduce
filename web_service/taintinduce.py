from flask import Blueprint, flash, redirect, render_template, request, session, url_for, send_file

import functools
import io
import base64

from worker_client import get_worker
from web_service.auth import login_required

bp = Blueprint('taintinduce', __name__)

@bp.route('/')
def index():
    worker = get_worker()
    rules = worker._get_rules()
    return render_template('taintinduce/index.html', rules=rules)

@bp.route('/rules/<arch_string>/<insn_bytestring>/info')
def rule_info(insn_bytestring, arch_string):
    worker = get_worker()
    return worker._get_rule_info(insn_bytestring, arch_string)


@bp.route('/rules/<arch_string>/<insn_bytestring>/dl')
def rule_dl(insn_bytestring, arch_string):
    worker = get_worker()
    rule_b64 = worker._get_rule_b64(insn_bytestring, arch_string)
    rule = base64.b64decode(rule_b64)
    rule_file = io.BytesIO(rule)
    return send_file(rule_file, mimetype='application/octet-stream',as_attachment=True, attachment_filename='{}_{}.rule'.format(arch_string, insn_bytestring))

@bp.route('/rules/<arch_string>/<insn_bytestring>/obs')
def view_obs(insn_bytestring, arch_string):
    worker = get_worker()
    obs_str = worker.view_obs(insn_bytestring, arch_string)
    return '<br/>'.join(obs_str)

@bp.route('/submit_job', methods=('GET', 'POST'))
@login_required
def submit_job():
    if request.method == 'POST':
        insn_bytestring = request.form['bytestring']
        arch_string = request.form['archstring']
        state_string = request.form['state_string']
        sid = session.get('user_session_id')
        error = None

        if not insn_bytestring or not arch_string:
            error = 'Please fill in both bytestring and archstring'

        if error is not None:
            flash(error)
        else:
            worker = get_worker()
            if state_string:
                worker.add_obs_job_check(sid, insn_bytestring, arch_string, state_string)
            else:
                worker.add_obs_job_check(sid, insn_bytestring, arch_string)
            return redirect(url_for('taintinduce.view_jobs'))
    return render_template('taintinduce/submit_job.html')

@bp.route('/view_jobs', methods=('GET', 'POST'))
@login_required
def view_jobs():
    worker = get_worker()
    jobs = worker.view_jobs()
    obsjobs = worker.view_obs_jobs()
    return render_template('taintinduce/view_jobs.html', jobs=jobs, obsjobs=obsjobs)
