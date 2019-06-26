#!/usr/bin/env python2

from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker

from service_core import _get_jobs, _get_obs_jobs, _obs_aio, _infer_aio, _set_job_process, _set_infer_process
from database.db_common import *

from multiprocessing import Process, Queue, Manager

import cPickle as pickle
import time
import argparse

def infer_worker(q):
    while True:
        jobid = q.get()
        _infer_aio(jobid)

def obs_worker(q):
    while True:
        jobid = q.get()
        _obs_aio(jobid)

def infer_worker_loop():
    num_infer = 5
    queue = Manager().Queue()
    worker_list = []
    for x in range(num_infer):
        worker_list.append(Process(target=infer_worker, args=(queue,)))
    for worker in worker_list:
        worker.start()
    while True:
        # Get a set of jobs from the database
        jobs = _get_jobs(False)
        if jobs.count() > 0:
            print('INFER: Found {} Jobs'.format(jobs.count()))
            for job_orm in jobs:
                jobid = job_orm.id
                _set_infer_process(jobid)
                queue.put(jobid)
        else:
            time.sleep(10)

def obs_worker_loop():
    num_obs = 5
    queue = Manager().Queue()
    worker_list = []
    for x in range(num_obs):
        worker_list.append(Process(target=obs_worker, args=(queue,)))

    for worker in worker_list:
        worker.start()
    while True:
        jobs = _get_obs_jobs(False)
        if jobs.count() > 0:
            print('OBS: Found {} Jobs'.format(jobs.count()))
            for obs_job_orm in jobs:
                jobid = obs_job_orm.id
                _set_job_process(jobid)
                queue.put(jobid)
        else:
            time.sleep(10)

def test():
    parser = argparse.ArgumentParser()
    parser.add_argument('bytestring')
    parser.add_argument('arch_string')
    args = parser.parse_args()

    bytestring = args.bytestring
    arch_string = args.arch_string
    _infer(bytestring, arch_string)

def main():
    num_obs = 1
    num_infer = 1
    obs_process = Process(target=obs_worker_loop)
    #obs_process.daemon = True
    infer_process = Process(target = infer_worker_loop)
    #infer_process.daemon = True

    try:
        print("Running Observation Job Loop")
        obs_process.start()
        print("Running Inference Job Loop")
        infer_process.start()
        while True:
            pass
    except KeyboardInterrupt:
        print("Killing Observation Job Loop")
        obs_process.terminate()
        print("Killing Inference Job Loop")
        infer_process.terminate()

if __name__ == '__main__':
    main()
    #test()
