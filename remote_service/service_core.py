#!/usr/bin/env python2

from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker, scoped_session

from multiprocessing import Process
import cPickle as pickle

import hashlib
import binascii
import base64
import os
import time

from observation_engine.observation import ObservationEngine
from inference_engine.inference import InferenceEngine
from disassembler.insn_info import InsnInfo
from taintinduce_common import *

from db_common import *

#parser = argparse.ArgumentParser()
#parser.add_argument('hostname')
#parser.add_argument('port')
#args = parser.parse_args()

engine = create_engine('sqlite:///remote_service/database.db', echo=True)
session_factory = scoped_session(sessionmaker(bind=engine))

def create_user(username, password):
    session = session_factory()
    hashed = hashlib.sha256(password).digest()
    new_user = User(name=username, password=hashed)
    session.add(new_user)
    session.commit()
    return new_user.id

def login_user(username, password):
    session = session_factory()
    hashed = hashlib.sha256(password).digest()
    results = session.query(User).filter_by(password=hashed)
    if results.count() == 1:
        # generates a random session id
        sid = binascii.hexlify(os.urandom(16))
        user_db = results.first()
        session_db = SessionORM(uid=user_db.id, sid=sid, login_time=time.time())
        user_db.sessions.append(session_db)
        session.commit()
        return session_db.sid
    else:
        return None

def logout_user(sid):
    session = session_factory()
    results = session.query(SessionORM).filter_by(sid=sid)
    if results.count() == 1:
        session_orm = results.first()
        session.delete(session_orm)

def view_jobs():
    session = session_factory()
    job_str = []
    results = session.query(JobORM)
    for job_orm in results:
        username = job_orm.session.user.name
        insn_bytestring = job_orm.insninfo.bytestring
        arch_string = job_orm.insninfo.arch_string
        job_str.append((username, insn_bytestring, arch_string))
    return job_str

def view_obs_jobs():
    session = session_factory()
    job_str = []
    results = session.query(ObservationJobORM)
    for job_orm in results:
        username = job_orm.session.user.name
        insn_bytestring = job_orm.bytestring
        arch_string = job_orm.arch_string
        job_str.append((username, insn_bytestring, arch_string))
    return job_str

def view_obs(bytestring, arch_string):
    session = session_factory()
    obs_str = []
    insn_info_orm = _get_insn_info(bytestring, arch_string)
    obs_str.append('<h1> Number of Observations: {} </h1>'.format(len(insn_info_orm.observations)))
    for obs_orm in insn_info_orm.observations:
        obs = pickle.loads(obs_orm.serialize_blob)
        obs_str.append('seed_in: {}'.format(repr(obs.seed_io[0])))
    return obs_str

def session2name(session_id):
    pass

def _get_rules():
    session = session_factory()
    results = session.query(RuleORM)
    return [(x.insninfo.arch_string, x.insninfo.bytestring) for x in results if x]

def _get_insn_info(bytestring, arch_string):
    session = session_factory()
    result = session.query(InstructionInfo).filter_by(bytestring=bytestring, arch_string=arch_string)
    if result.count() == 1:
        insn_info_db = result.first()
        return insn_info_db
    elif result.count() == 0:
        return None
    else:
        raise Exception("Expected 1 or 0 entries, got {}!".format(len(result)))

def _get_rule(bytestring, arch_string):
    insn_info_db = _get_insn_info(bytestring, arch_string)
    if insn_info_db:
        return pickle.loads(insn_info_db.rule[0].serialize_blob)
    else:
        return None

def _get_rule_info(bytestring, arch_string):
    insn_info_db = _get_insn_info(bytestring, arch_string)
    insn_info = pickle.loads(insn_info_db.insinfo_serialize)
    rule = pickle.loads(insn_info_db.rule[0].serialize_blob)
    if rule:
        info_string = '<h1> {} </h1>'.format(bytestring)
        info_string += '<h1> {} </h1>'.format(insn_info.asm_str)
        return info_string + rule.web_string()
    else:
        return "None"

def _get_rule_b64(bytestring, arch_string):
    rule = _get_rule(bytestring, arch_string)
    rule_pkl = pickle.dumps(rule)
    return base64.b64encode(rule_pkl)

def _set_insn_info(bytestring, arch_string):
    session = session_factory()
    byte = binascii.unhexlify(bytestring)
    # call disassembler to get insn_info
    insn_info = InsnInfo(arch_string, bytestring)
    insinfo_serialize = pickle.dumps(insn_info)
    state_format = 'TODO' #TODO: Fix
    cond_info = 'TODO' #TODO: Fix
    insn_info_db = InstructionInfo(bytestring=bytestring, state_format=state_format, cond_info=cond_info, arch_string=arch_string, insinfo_serialize=insinfo_serialize)
    session.add(insn_info_db)
    session.commit()
    return None

def _get_observations(bytestring, arch_string):
    obs_list = []
    insn_info_db = _get_insn_info(bytestring, arch_string)
    if not insn_info_db:
        return None
    for obs_db in insn_info_db.observations:
        obs = pickle.loads(obs_db.serialize_blob)
        obs_list.append(obs)
    return obs_list

def _gen_observations(bytestring, arch_string):
    session = session_factory()
    byte = binascii.unhexlify(bytestring)
    # get the instruction info from the database
    insn_info_db = _get_insn_info(bytestring, arch_string)
    if not insn_info_db:
        return None
    insn_info = pickle.loads(insn_info_db.insinfo_serialize)
    obs_engine = ObservationEngine(bytestring, arch_string, insn_info.reg_set)
    obs = obs_engine.observe_insn()

    for observation in obs:
        state_in = observation.seed_io[0]
        state_in_hash = hashlib.sha256(str(state_in)).digest()
        serialized = pickle.dumps(observation)
        observation_db = ObservationORM(serialize_blob=serialized, state_in_hash=state_in_hash)
        insn_info_db.observations.append(observation_db)
    session.commit()

def _add_observations(bytestring, arch_string, state_string):
    """Generate additional observation for the provided input
        states.

        Args:
            bytestring (str): instruction bytes in hex encoding
            arch_string (str): architecture string
            states (list of State): list of states that 
                for which the observations are generated

        Returns:
            None
    """
    # get a list of state hashes to be used to see if it exists
    # in the database
    session = session_factory()
    insn_info_db = _get_insn_info(bytestring, arch_string)
    if not insn_info_db:
        return None
    states = [State(x,y) for x,y in eval(state_string)]
    insinfo = pickle.loads(insn_info_db.insinfo_serialize)
    state_hashes = {hashlib.sha256(str(x)).digest():x for x in states}
    exist_obs = {x.state_in_hash for x in insn_info_db.observations}
    state_hash_new = set(state_hashes) - exist_obs
    obs_engine = ObservationEngine(bytestring, arch_string, insinfo)
    for state_hash in state_hash_new:
        obs = obs_engine.add_new_seed(state_hashes[state_hash])
        serialized = pickle.dumps(obs)
        obs_orm = ObservationORM(serialize_blob=serialized, state_in_hash = state_hash)
        insn_info_db.observations.append(obs_orm)
    session.commit()

def _infer(bytestring, arch_string):
    # get stuff from db
    session = session_factory()
    insn_info_db = _get_insn_info(bytestring, arch_string)
    if not insn_info_db:
        return None
    insn_info = pickle.loads(insn_info_db.insinfo_serialize)
    obs = [pickle.loads(x.serialize_blob) for x in insn_info_db.observations]

    infer_engine = InferenceEngine()
    rule = infer_engine.infer(insn_info.bytestring, insn_info.arch, insn_info.reg_set, obs, None)
    serialized = pickle.dumps(rule)
    # write rule to db
    rule_db = RuleORM(serialize_blob=serialized)
    insn_info_db.rule.append(rule_db)
    session.commit()
    return True

def _add_obs_job_check(sid, bytestring, arch_string, statestring):
    if not _check_session(sid):
        return 'ERROR! Session not found!'
    _add_obs_job(sid, bytestring, arch_string, statestring)

def _add_obs_job(sid, bytestring, arch_string, statestring):
    session = session_factory()
    obs_job = ObservationJobORM(sid=sid, bytestring=bytestring, arch_string=arch_string, statestring=statestring)
    session.add(obs_job)
    session.commit()
    return None

def _add_job(bytestring, arch_string, sid):
    session = session_factory()
    insn_info_db = _get_insn_info(bytestring, arch_string)
    jobs_db = JobORM(sid=sid)
    insn_info_db.job.append(jobs_db)
    session.commit()
    return None

def _end_job(job_db):
    session = session_factory()
    session.delete(job_db)
    session.commit()
    return None

def _get_obs_jobs(is_all=True):
    session = session_factory()
    if is_all:
        jobs = session.query(ObservationJobORM)
    else:
        jobs = session.query(ObservationJobORM).filter_by(process=0)
    return jobs

def _get_jobs(is_all=True):
    session = session_factory()
    if is_all:
        jobs = session.query(JobORM)
    else:
        jobs = session.query(JobORM).filter_by(process=0)
    return jobs

def _check_session(sid):
    session = session_factory()
    results = session.query(SessionORM).filter_by(sid=sid)
    return results.count() > 0


def _process_request(bytestring, arch_string, statestring=None, taint=None):
    session = session_factory()
    print('PROCESS')
    """Process the request of a user
        Args:
            bytestring (str): instruction bytes in hex form
            states (list of State): optional states that are 
                provided by the user (optional)
            taint (State): Taint status to be propagated 
                (optional)
    """
    # let's get all the information we can in the database
    insn_info = _get_insn_info(bytestring, arch_string)
    if not insn_info:
        # insn_info for bytestring don't exist,
        # populate the insn_info
        _set_insn_info(bytestring, arch_string)

    insn_info = _get_insn_info(bytestring, arch_string)

    if not statestring and insn_info.rule:
        rule = _get_rule(bytestring, arch_string)
        return rule

    # at this point, insn_info will for sure contain the 
    # necessary information and rule does not exist

    # check if observations exist
    if not insn_info.observations:
        # obs does not exist, generate the observation
        _gen_observations(bytestring, arch_string)

    if statestring:
        _add_observations(bytestring, arch_string, statestring)
        print(insn_info.rule)
        if insn_info.rule:
            for rule_orm in insn_info.rule:
                session.delete(rule_orm)
            session.commit()

    # ZL: http is stateless, we will add it to a job queue for the worker_infer.py consumer
    #_infer(bytestring, arch_string)
    # we'll add it outside... process is just to prep
    return None

def _infer_aio(infer_jobid):
    job_orm = get_orm(JobORM, infer_jobid)
    bytestring = job_orm.insninfo.bytestring
    arch_string = job_orm.insninfo.arch_string
    if _infer(bytestring, arch_string):
        _end_job(job_orm)

def _obs_aio(obs_jobid):
    obs_job_orm = get_orm(ObservationJobORM, obs_jobid)
    bytestring = obs_job_orm.bytestring
    arch_string = obs_job_orm.arch_string
    statestring = obs_job_orm.statestring
    sid = obs_job_orm.sid
    if _process_request_add_job(bytestring, arch_string, None, sid):
        _end_job(obs_job_orm)

def _process_request_add_job(bytestring, arch_string, statestring, sid):
    # TODO: Currently ignore the statestring
    # TODO: Shift the job system into here... :(
    _process_request(bytestring, arch_string)
    _add_job(bytestring, arch_string, sid)
    return True

def _set_job_process(jobid):
    session = session_factory()
    obs_job_orm = get_orm(ObservationJobORM, jobid)
    obs_job_orm.process = 1
    session.commit()

def _set_infer_process(jobid):
    session = session_factory()
    job_orm = get_orm(JobORM, jobid)
    job_orm.process = 1
    session.commit()

def get_orm(orm_type, id):
    session = session_factory()
    result = session.query(orm_type).filter_by(id=id)
    if result.count() == 1:
        orm = result.first()
        return orm
    elif result.count() == 0:
        return None
    else:
        raise Exception("Expected 1 or 0 entries, got {}!".format(len(result)))

def _update_db():
    session = session_factory()
    session.commit()

def main():
    _process_request('5d', 'X86')
    _process_request('53', 'X86')
    _process_request('54', 'X86')
    _process_request('55', 'X86')
    _process_request('56', 'X86')
    _process_request('57', 'X86')

if __name__ == '__main__':
    main()

