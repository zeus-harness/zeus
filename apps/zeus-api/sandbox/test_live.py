"""Explicit isolated Linux acceptance; never points at the daily API or its database."""
import base64
import json
import pathlib
import threading
import time
import unittest
import urllib.request
import uuid

CONFIG = dict(line.split('=', 1) for line in pathlib.Path('.zeus/sandbox-test.env').read_text().splitlines() if '=' in line)
BASE = CONFIG['ZEUS_SANDBOX_URL']
TOKEN = CONFIG['ZEUS_SANDBOX_TOKEN']
ENVIRONMENT = CONFIG['ZEUS_SANDBOX_ENVIRONMENT']


def post(path, body, token=TOKEN):
    request = urllib.request.Request(BASE + path, json.dumps(body).encode(),
        {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)


def run(script, files=None, timeout=20, renew=True, job=None):
    job = job or str(uuid.uuid4())
    done = threading.Event()
    def heartbeat():
        while not done.wait(.5):
            try: post('jobs/' + job + '/renew', {})
            except Exception: pass
    thread = threading.Thread(target=heartbeat)
    if renew: thread.start()
    try:
        return post('execute', {'job_id': job, 'environment': ENVIRONMENT, 'script': script,
            'timeout_seconds': timeout, 'files': files or []})
    finally:
        done.set()
        if renew: thread.join()


class LinuxAcceptance(unittest.TestCase):
    def test_toolchains_and_file_changes(self):
        result = run('set -eu; git --version; node --version; npm --version; pnpm --version; python3 --version; rustc --version; cargo --version; printf changed > result.txt; node -e "console.log(2+2)"; python3 -c "print(3+3)"; printf "fn main(){println!(\\\"rust-ok\\\");}" > /tmp/main.rs; rustc /tmp/main.rs -o /tmp/main; /tmp/main', timeout=30)
        self.assertEqual(result['exit_code'], 0, result['output'])
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(any(f['path'] == 'result.txt' and base64.b64decode(f['data']) == b'changed' for f in result['files']))
        print('Verified toolchains:', result['output'].splitlines()[:7])

    def test_identity_readonly_network_and_seccomp(self):
        result = run('''set -eu
[ "$(id -u)" = 10001 ]
grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status
grep -q 'Seccomp:[[:space:]]*2' /proc/self/status
grep -q 'CapEff:[[:space:]]*0000000000000000' /proc/self/status
[ ! -e /opt/zeus/broker.py ]
[ ! -e /workspace/.git ]
[ -z "${ZEUS_SANDBOX_TOKEN:-}" ]
! touch /usr/bin/forbidden 2>/dev/null
python3 - <<'PY'
import socket, ctypes, errno
s=socket.socket(); s.settimeout(.3)
try: s.connect(('1.1.1.1',443))
except OSError: pass
else: raise AssertionError('network unexpectedly accessible')
libc=ctypes.CDLL(None, use_errno=True)
assert libc.unshare(0x40000000) == -1
assert ctypes.get_errno() == errno.EPERM
PY
''')
        self.assertEqual(result['exit_code'], 0, result['output'])

    def test_timeout_kills_descendants(self):
        start = time.monotonic()
        result = run('sleep 120 & wait', timeout=1)
        self.assertEqual(result['status'], 'timeout')
        self.assertLess(time.monotonic()-start, 8)

    def test_lost_lease_stops_work(self):
        start = time.monotonic()
        result = run('sleep 120', timeout=30, renew=False)
        self.assertEqual(result['status'], 'canceled')
        self.assertLess(time.monotonic()-start, 16)

    def test_no_duplicate_execution(self):
        job = str(uuid.uuid4())
        self.assertEqual(run('true', job=job)['exit_code'], 0)
        with self.assertRaises(urllib.error.HTTPError) as error: run('echo repeat', job=job)
        self.assertEqual(error.exception.code, 409)

    def test_unauthenticated_request_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as error: post('execute', {}, token='invalid')
        self.assertEqual(error.exception.code, 401)

    def test_pid_and_disk_limits(self):
        result = run('''python3 - <<'PY'
import subprocess
children=[]
try:
    for _ in range(180): children.append(subprocess.Popen(['sleep','30']))
except OSError: pass
else: raise AssertionError('PID limit not enforced')
finally:
    for child in children: child.terminate()
    for child in children: child.wait()
try:
    with open('/tmp/large','wb') as f:
        for _ in range(90): f.write(b'x' * 1048576)
except OSError: pass
else: raise AssertionError('disk limit not enforced')
PY
''')
        self.assertEqual(result['exit_code'], 0, result['output'])

    def test_output_is_bounded(self):
        result = run("python3 -c 'print(\"x\"*100000)'", timeout=5)
        self.assertEqual(result['status'], 'output_limit')
        self.assertLessEqual(len(result['output'].encode()), 65536)
        self.assertEqual(result['files'], [])

    def test_symlink_output_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            run('ln -s /etc/passwd stolen')
        self.assertEqual(error.exception.code, 422)

    def test_cancel_and_concurrent_filesystem_isolation(self):
        job = str(uuid.uuid4())
        results = []
        thread = threading.Thread(target=lambda: results.append(run('echo private > marker; sleep 30', job=job)))
        thread.start()
        try:
            for _ in range(50):
                if post('jobs/' + job + '/renew', {})['active']: break
                time.sleep(.1)
            else: self.fail('first job did not start')
            second = run('[ ! -e marker ]; echo independent > other')
            self.assertEqual(second['exit_code'], 0)
            self.assertEqual([f['path'] for f in second['files']], ['other'])
            post('jobs/' + job + '/cancel', {})
        finally:
            thread.join(timeout=35)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]['status'], 'canceled')

    def test_memory_limit(self):
        result = run("python3 -c 'print(\"memory-start\",flush=True); data=bytearray(800*1024*1024)'", timeout=10)
        self.assertIn('memory-start', result['output'])
        self.assertNotEqual(result['exit_code'], 0)

if __name__ == '__main__': unittest.main()
