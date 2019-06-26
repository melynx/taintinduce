#!/usr/bin/env python

import pyjsonrpc
import threading
import os
import cPickle as pickle

from taintinduce_common import query_yes_no

def log(mystring):
    print("SquirrelFlowDB: {}".format(mystring))

class TaintInduceThread(threading.Thread):
    def __init__(self, thread_id, t_count_list, remote_client, worklist, lock, write_path=None):
        threading.Thread.__init__(self)
        self.tid = thread_id
        self.t_count_list = t_count_list
        self.remote = remote_client
        self.worklist = worklist
        self.lock = lock
        self.write_path = write_path

    def run(self):
        while (True):
            self.lock.acquire()
            if len(self.worklist) == 0:
                self.lock.release()
                break
            work_string = self.worklist.pop()
            archstring, raw_bytes = work_string.split('_')
            self.lock.release()
            self.t_count_list[self.tid][1] = raw_bytes
            print("{}: {} ({})".format(self.remote.url, raw_bytes, archstring))
            try:
                result = self.remote.infer(archstring, raw_bytes)
            except:
                self.lock.acquire()
                self.worklist.add(work_string)
                self.lock.release()
                break
            self.t_count_list[self.tid][0] += 1
            print("{}: {} - ({}) DONE!".format(self.remote.url, raw_bytes, len(result)))
            rule_path = os.path.join(self.write_path, '{}_{}'.format(archstring, raw_bytes))
            open(rule_path, 'wb').write(result)

class SquirrelFlowDB(object):
    def __init__(self, rule_path='rule/', config_path='squirrelflow.cfg'):
        self.rules = {}
        self.rule_path = rule_path
        self.config_path = config_path
        log("Rule path is {}".format(rule_path))
    
    def check_rules(self, archstring, insn_set, remote=True):
        rule_set = set(os.listdir(self.rule_path))
        insn_set = {'{}_{}'.format(archstring, x) for x in insn_set}
        missing_rules = insn_set - rule_set
        if missing_rules:
            total_jobs = len(missing_rules)
            choice = query_yes_no("{} missing rules found! Train them? -Remote:{}- ".format(total_jobs, remote))
            if choice:
                if remote:
                    self.remote_training(missing_rules)
                else:
                    self.local_training(missing_rules)

                #for insn_bytestring in new_rules:
                #    self.rules[insn_bytestring] = new_rules[insn_bytestring]
            print("Done! Processed {} rules...".format(total_jobs))

    def remote_training(self, missing_rules):
        # create the process for the remote connections
        thread_lock = threading.Lock()
        workers = []
        t_count_list = []

        with open(self.config_path, 'r') as myfile:
            connection_strings = set()
            for line in (myfile):
                if line[0] == '#':
                    continue
                connection_strings.add(line.rstrip())

            for tid, line in enumerate(connection_strings):
                client_worker = pyjsonrpc.HttpClient(url=line)
                worker = TaintInduceThread(tid, t_count_list, client_worker, missing_rules, thread_lock, self.rule_path)
                t_count_list.append([0, None])
                workers.append(worker)

        for worker in workers:
            worker.start()

        for worker in workers:
            worker.join()

        print('----Processed Jobs Stats----')
        for worker in workers:
            print('{}: {}'.format(worker.remote.url, t_count_list[worker.tid][0]))

    def get_rule(self, archstring, bytestring):
        rule_name = '{}_{}'.format(archstring, bytestring)
        if rule_name not in self.rules:
            rule_path = os.path.join(self.rule_path, rule_name)
            self.rules[rule_name] = pickle.load(open(rule_path, 'rb'))
        return self.rules[rule_name]

