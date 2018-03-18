#!/usr/bin/env python3

import json
import http.server

from ethereum import utils
from symevm import util, code, state, cfg, vm
import evm

_sessions = {}

def new_session():
    contracts, _ = evm.load_state('examples/slock.json')
    return {'global_state': contracts }

class Handler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        # TODO ideally don't go str->bytes, but self.wfile doesn't support str
        # (only bytes)
        s = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-Length', len(s))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(s)

    def _fail(self, msg, code=400):
        self._send_json(dict(error=msg), code=code)

    def _start_session(self):
        if _sessions:
            next_id = max(_sessions.keys()) + 1
        else:
            next_id = 0
        _sessions[next_id] = new_session()
        self._send_json({'id': str(next_id)})

    def _read_json(self):
        return json.load(self.rfile)

    def _route(self, path, session, data):
        print(path, data, session)
        if path == 'state':
            session.setdefault('global_state', {})
            if data:
                assert False, 'TODO: update state from remote'
                for addr, info in data.items():
                    session['global_state'].setdefault(int(addr, 0), {}).update(info)
            self._send_json({addr: [] for addr, _ in session['global_state'].items()})
        elif path == 'contracts':
            session.setdefault('global_state', {})
            self._send_json([hex(addr) for addr, _ in session['global_state'].items()])
        elif path == 'disassemble':
            addr = int(data['addr'], 0)
            code = session['global_state'][addr].code
            dis = [[pc, instr] for pc, instr in util.disassemble_core(code._code, 0, len(code._code) - 1)]
            self._send_json(dis)
        elif path == 'cfg':
            addr = int(data['addr'], 0)
            code = session['global_state'][addr].code
            base_t = state.TransactionState('base', addr, session['global_state'],
                initial_storage_policy=state.storage_any_policy)
            coverage = {}
            print('start: cfg for {}'.format(addr))
            root = cfg.get_cfg(code, base_t, False, False, coverage=coverage)
            print('end: cfg for {}'.format(addr))
            self._send_json(cfg.to_json(root))
        else:
            self._fail('Unknown route', code=404)

    def do_POST(self):
        if self.path == '/start':
            self._start_session()
        else:
            components = self.path.lstrip('/').split('/')
            try:
                session_id = int(components[0])
                session = _sessions[session_id]
                rest = '/'.join(components[1:])
            except (IndexError, ValueError, KeyError):
                self._fail('No session')
            else:
                size = int(self.headers.get('Content-Length', 0))
                if size:
                    data = json.loads(self.rfile.read(size).decode('UTF-8'))
                else:
                    data = None
                self._route(rest, session, data)

    def do_OPTIONS(self):
        # Browsers send an OPTIONS request to check security policy or something
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

def start_server(bind="", port=8080):
    server = http.server.HTTPServer((bind, port), Handler)
    server.serve_forever()

if __name__ == '__main__':
    start_server()
