#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 BIFIT

import argparse
import json
import ssl
import sys

if sys.version_info >= (3, ):
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError
else:
        from urllib2 import Request, urlopen, HTTPError


class MitigatorException(BaseException):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class RequestEx(Request):
    def __init__(self, *args, **kwargs):
        self._method = kwargs.pop('method', None)
        Request.__init__(self, *args, **kwargs)

    # 'add_data(str)' removed in Python 3.4 in favour of 'Request.data: bytes'
    def add_data(self, data):
        if hasattr(self, 'data'):       self.data = data.encode('utf-8')
        else:
            Request.add_data(self, data)

    # Request.method was added in Python 3.3
    def get_method(self):
        return self._method if self._method else Request.get_method(self)


def make_request(options, uri, method=None, token=None, policy=None, data=None):
    url = 'https://%s/api/v4/%s' % (options.server, uri)
    if policy is not None:
        url += '?policy=%d' % policy

    request = RequestEx(url, method=method)
    if token is not None:
        request.add_header('X-Auth-Token', token)
    if data is not None:
        request.add_data(json.dumps(data))

    if not hasattr(options, 'ctx'):
        ctx = ssl.create_default_context()
        if options.no_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        options.ctx = ctx

    try:
        response = urlopen(request, context=options.ctx)
    except HTTPError as e:
        try:
            raise MitigatorException(e.fp.read())
        except IOError:
            raise e
    return json.load(response)['data']


def parse_args():
    def add_switch(root):
        switch = root.add_parser('switch')
        states = switch.add_subparsers(dest='state')
        states.add_parser('on')
        states.add_parser('off')

    def add_countermeasure(root, name):
        countermeasure = root.add_parser(name)
        actions = countermeasure.add_subparsers(dest='action')
        add_switch(actions)
        return actions

    parser = argparse.ArgumentParser()

    parser.add_argument('--server', required=True, help='Mitigator host')
    parser.add_argument('--user', required=True, help='Mitigator login')
    parser.add_argument('--password', required=True, help='Mitigator password')
    parser.add_argument('--policy', help='policy ID (as shown in URL)', type=int)
    parser.add_argument('--no-verify', help='disable TLS certificate validation', action='store_true')

    tools = parser.add_subparsers(dest='tool')

    tbl = tools.add_parser('tbl')
    subs = tbl.add_subparsers(dest='action')

    block = subs.add_parser('block')
    block.add_argument('-i', '--ip', required=True, help='IP address to block')
    block.add_argument('-t', '--time', required=True, help='block time in seconds', type=int)

    unblock = subs.add_parser('unblock')
    unblock.add_argument('-i', '--ip', required=True, help='IP address to unblock')

    add_countermeasure(tools, 'tcp')
    add_countermeasure(tools, 'acl')
    add_countermeasure(tools, 'sorb')

    add_countermeasure(tools, 'state')

    return parser.parse_args()


def run_tbl(options, token):
    if options.action == 'block':
        make_request(options, 'tempBlacklist/items',
                     token=token, policy=options.policy,
                     data={'items': [{'prefix': options.ip, 'ttl': options.time}]})
    elif options.action == 'unblock':
        make_request(options, 'tempBlacklist/items', method='DELETE',
                     token=token, policy=options.policy,
                     data={'items': [{'prefix': options.ip}]})


def run_scope_switch(prefix, options, token):
    if options.action != 'switch':
        return False

    state = 1 if options.state == 'on' else 0
    make_request(options, '%s/switch' % prefix, method='PUT',
                 token=token, policy=options.policy,
                 data={'switch': state})
    return True


def run_tcp(*args):
    run_scope_switch('tcpFloodProt', *args)


def run_acl(*args):
    run_scope_switch('acl', *args)


def run_sorb(*args):
    run_scope_switch('sourceLimiter', *args)


def run_switch(options, token):
    scope = 'toggle' if options.policy is not None else 'router'
    run_scope_switch(scope, options, token)


if __name__ == '__main__':
    options = parse_args()

    data = make_request(options, 'users/session',
                        data={'username': options.user, 'password': options.password})
    token = data['token']

    if options.tool == 'tbl':
        run_tbl(options, token)
    elif options.tool == 'tcp':
        run_tcp(options, token)
    elif options.tool == 'acl':
        run_acl(options, token)
    elif options.tool == 'sorb':
        run_sorb(options, token)
    elif options.tool == 'state':
        run_switch(options, token)