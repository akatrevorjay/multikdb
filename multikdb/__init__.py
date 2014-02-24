#!/usr/bin/env python

import logging
log = logging.getLogger(__name__)

import os
import re
import sys

from . import config
from .pretty import pp as pprint
#from pprint import pprint

try:
    from keepass import kpdb
except ImportError:
    from .keepass import kpdb

try:
    from pexpect import pxssh
except ImportError:
    log.warning('Missing pexpect.pxssh.')
    pass


class KeepassUnified(object):
    def __init__(self, kdbs):
        self._load_kpdbs(kdbs)
        self._populate_entries()

    def _load_kpdbs(self, kdbs):
        self._dbs = dict()
        for name, conf in kdbs.iteritems():
            if 'filename' not in conf:
                conf['filename'] = os.path.join(config.default_path,
                                                '%s.kdb' % name)
            if not os.path.isfile(conf['filename']):
                log.warning('Could not load kdb "%s".', conf['filename'])
                continue
            self._dbs[name] = kpdb.Database(conf['filename'],
                                            conf['master_password'])

    def _populate_entries(self):
        self._entries = []

        for db_name, db in self._dbs.iteritems():
            for entry in db.entries:
                if not entry.title:
                    continue

                group_name = None
                if entry.groupid in db.groups:
                    group_name = db.groups[entry.groupid].group_name

                self._entries.append(dict(
                    db=db_name,
                    #group_id=entry.groupid,
                    group=group_name,

                    title=entry.title,
                    #uuid=entry.uuid,
                    username=entry.username,
                    password=entry.password,
                    url=entry.url,
                    comment=entry.notes,
                ))

    def _search_entry_bool(self, entry, params, kwparams):
        for param in params:
            found = False
            for k, v in entry.iteritems():
                if re.search(param, str(v), re.MULTILINE):
                    found = True
                    break
            if not found:
                return False
        for k, v in kwparams.iteritems():
            if not re.search(v, str(entry.get(k)), re.MULTILINE):
                return False
        return True

    def search(self, *params, **kwparams):
        return filter(
            lambda x: self._search_entry_bool(x, params, kwparams),
            self._entries)


def search():
    ku = KeepassUnified(config.kdbs)
    args = sys.argv[1:]
    if not args:
        return
    pprint(ku.search(*args))


def ssh():
    ku = KeepassUnified(config.kdbs)
    args = sys.argv[1:]
    if not args:
        return
    results = ku.search(*args)
    pprint(results)
    if len(results) == 1:
        entry = results[0]

        host = entry['title']
        username = entry['username']
        password = entry['password']

        ## TODO For some reason sshpass will *not* work this script.
        ## it just returns "permission denied".
        #env = os.environ.copy()
        #env = dict()
        #env['SSHPASS'] = password
        ##pprint(env)
        #args = ['/usr/bin/sshpass',
        #           '-e',
        #           #'-p%s' % password,
        #           #'-p', password,
        #           #'-p"%s"' % password,
        #           #'-p %s' % password,
        #           '/usr/bin/ssh',
        #           #'-o', 'ControlMaster=auto',
        #           '-o', 'StrictHostKeyChecking=no',
        #           '%s@%s' % (username, host),
        #           env]
        #pprint(args)
        #os.execle(*args)

        #print 'SSHPASS="%s" sshpass -e ssh "%s@%s"' % (
        #    entry['password'],
        #    entry['username'],
        #    entry['title'],
        #    )

        # pexpect sucks a hard one for interactive SSH but it's all we got as of yet.
        ssh = pxssh.pxssh()
        ssh.login(host, username, password)
        ssh.interact()
