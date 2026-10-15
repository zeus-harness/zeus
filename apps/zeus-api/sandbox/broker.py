"""Private Linux execution adapter. No scheduler, database access or host mounts.

Only the authenticated Zeus runtime can invoke this service. Its small protocol
cannot choose images, host paths, network, environment variables or resource caps.
"""
import base64
import hmac
import json
import os
import selectors
import shutil
import stat
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath

MAX_BYTES = 32 * 1024 * 1024
MAX_FILES = 4096
MAX_JSON = 48 * 1024 * 1024
MAX_LOG = 65536
ROOT = Path('/opt/zeus/rootfs')
JOBS = Path('/run/zeus-jobs')
STATE = Path('/var/lib/zeus-sandbox')
CGROUP = Path('/sys/fs/cgroup/zeus-sandbox')
POLICY = '/opt/zeus/seccomp.bpf'
TOKEN = os.environ.get('ZEUS_SANDBOX_TOKEN', '')
ENVIRONMENT = os.environ.get('ZEUS_SANDBOX_ENVIRONMENT', '')
SLOTS = threading.BoundedSemaphore(2)
LOCK = threading.Lock()
ACTIVE = {}


def valid_environment(value):
    return isinstance(value, str) and len(value) == 71 and value.startswith('sha256:') and all(c in '0123456789abcdef' for c in value[7:])


def path_parts(value):
    if not isinstance(value, str) or not value or len(value.encode()) > 1024 or '\\' in value or '\0' in value:
        raise ValueError('invalid_path')
    parts = value.split('/')
    if any(p in ('', '.', '..') or p.lower() == '.git' for p in parts) or PurePosixPath(value).is_absolute():
        raise ValueError('invalid_path')
    return parts


def decode_files(files):
    if not isinstance(files, list) or len(files) > MAX_FILES:
        raise ValueError('file_limit')
    result, size, names = [], 0, set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {'path', 'data', 'executable'} or type(item['executable']) is not bool:
            raise ValueError('invalid_file')
        parts = path_parts(item['path'])
        if item['path'] in names:
            raise ValueError('duplicate_file')
        names.add(item['path'])
        data = base64.b64decode(item['data'], validate=True)
        size += len(data)
        if size > MAX_BYTES:
            raise ValueError('file_limit')
        result.append((parts, data, item['executable']))
    return result


def snapshot(root):
    result, size, entries = [], 0, 0
    def traversal_error(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=traversal_error):
        if Path(directory) == root:
            dirs[:] = [name for name in dirs if name != '.git']
            files[:] = [name for name in files if name != '.git']
        for name in dirs + files:
            file = Path(directory, name)
            info = file.lstat()
            entries += 1
            if entries > MAX_FILES or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError('unsafe_output_file')
            relative = file.relative_to(root).as_posix()
            path_parts(relative)
            if stat.S_ISREG(info.st_mode):
                size += info.st_size
                if size > MAX_BYTES or info.st_nlink != 1:
                    raise ValueError('output_file_limit')
                result.append({'path': relative, 'data': base64.b64encode(file.read_bytes()).decode(),
                               'executable': bool(info.st_mode & 0o111)})
    return result


def command(args):
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=10, env={'PATH': '/usr/bin:/bin'})


def kill_group(group):
    if group.exists():
        (group / 'cgroup.kill').write_text('1')
        for _ in range(100):
            if 'populated 0' in (group / 'cgroup.events').read_text():
                return
            time.sleep(.02)
        raise RuntimeError('sandbox_cleanup_failed')


def execute(job_id, request, files):
    group, directory = CGROUP / job_id, JOBS / job_id
    mounted, process = False, None
    try:
        group.mkdir()
        for name, value in {'cpu.max': '100000 100000', 'memory.max': str(512 * 1024 * 1024),
                            'memory.swap.max': '0', 'memory.oom.group': '1', 'pids.max': '128'}.items():
            (group / name).write_text(value)
        directory.mkdir(mode=0o700)
        command(['/bin/mount', '-t', 'tmpfs', '-o', 'size=64m,nosuid,nodev,mode=0755', 'tmpfs', str(directory)])
        mounted = True
        work, temporary = directory / 'workspace', directory / 'tmp'
        for target in (work, temporary):
            target.mkdir(mode=0o700)
            os.chown(target, 10001, 10001)
        for parts, data, executable in files:
            target = work.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o700 if executable else 0o600)
            os.chown(target, 10001, 10001)
            parent = target.parent
            while parent != work:
                os.chown(parent, 10001, 10001)
                parent = parent.parent
        script = directory / 'script'
        script.write_text(request['script'])
        script.chmod(0o444)
        with LOCK:
            state = ACTIVE[job_id]
            if state['cancel']:
                raise RuntimeError('sandbox_canceled')
        process = subprocess.Popen(['/usr/bin/python3', '/opt/zeus/child.py', str(group), str(ROOT),
                                    str(work), str(temporary), str(script), POLICY],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env={'PATH': '/usr/bin:/bin'}, start_new_session=True)
        output, status = bytearray(), 'completed'
        deadline = time.monotonic() + request['timeout_seconds']
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while process.poll() is None:
                with LOCK:
                    canceled = state['cancel'] or time.monotonic() > state['lease']
                if canceled or time.monotonic() > deadline:
                    status = 'canceled' if canceled else 'timeout'
                    break
                for key, _ in selector.select(.1):
                    data = os.read(key.fd, 8192)
                    if not data:
                        selector.unregister(key.fileobj)
                    output.extend(data)
                if len(output) > MAX_LOG:
                    status = 'output_limit'
                    break
        finally:
            selector.close()
        # Kill background descendants even after a normal shell exit; only then inspect files.
        kill_group(group)
        process.wait(timeout=5)
        output.extend(process.stdout.read(MAX_LOG + 1 - min(len(output), MAX_LOG + 1)))
        if len(output) > MAX_LOG:
            status = 'output_limit'
        return {'status': status, 'exit_code': process.returncode,
                'output': output[:MAX_LOG].decode('utf-8', errors='replace'),
                'files': snapshot(work) if status == 'completed' else []}
    finally:
        try:
            kill_group(group)
            if process:
                process.wait(timeout=5)
            if mounted:
                command(['/bin/umount', str(directory)])
            if directory.exists():
                directory.rmdir()
            if group.exists():
                group.rmdir()
        finally:
            with LOCK:
                ACTIVE.pop(job_id, None)


class Handler(BaseHTTPRequestHandler):
    # Deliberately no request logging: paths, bodies and auth headers remain private.
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        data = json.dumps(body, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        self.connection.settimeout(10)
        if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + TOKEN):
            self.reply(401, {'error': 'unauthorized'})
            return
        if self.path == '/health':
            self.reply(200, {'environment': ENVIRONMENT})
            return
        if self.path.startswith('/jobs/'):
            parts = self.path.split('/')
            if len(parts) != 4 or parts[3] not in ('renew', 'cancel'):
                self.reply(404, {'error': 'not_found'})
                return
            with LOCK:
                state = ACTIVE.get(parts[2])
                if state:
                    if parts[3] == 'cancel':
                        state['cancel'] = True
                    else:
                        state['lease'] = time.monotonic() + 10
            self.reply(200, {'active': state is not None})
            return
        if self.path != '/execute':
            self.reply(404, {'error': 'not_found'})
            return
        acquired = False
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_JSON:
                raise ValueError('request_limit')
            request = json.loads(self.rfile.read(length))
            if set(request) != {'job_id', 'environment', 'script', 'timeout_seconds', 'files'}:
                raise ValueError('invalid_request')
            job_id = request['job_id']
            if str(uuid.UUID(job_id)) != job_id or request['environment'] != ENVIRONMENT:
                raise ValueError('environment_or_job_mismatch')
            if not isinstance(request['script'], str) or not 0 < len(request['script'].encode()) <= 16384 or '\0' in request['script']:
                raise ValueError('invalid_script')
            if type(request['timeout_seconds']) is not int or not 1 <= request['timeout_seconds'] <= 300:
                raise ValueError('invalid_timeout')
            files = decode_files(request['files'])
            acquired = SLOTS.acquire(blocking=False)
            if not acquired:
                self.reply(503, {'error': 'sandbox_capacity'})
                return
            # Durable tombstone: retries, disconnects and adapter restarts never repeat a job.
            with (STATE / job_id).open('x') as tombstone:
                tombstone.flush()
                os.fsync(tombstone.fileno())
            directory_fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            with LOCK:
                ACTIVE[job_id] = {'lease': time.monotonic() + 10, 'cancel': False}
            self.reply(200, execute(job_id, request, files))
        except FileExistsError:
            self.reply(409, {'error': 'sandbox_outcome_unknown'})
        except (ValueError, KeyError, TypeError):
            self.reply(422, {'error': 'sandbox_invalid_input_or_output'})
        except Exception:
            self.reply(500, {'error': 'sandbox_execution_failed'})
        finally:
            if acquired:
                SLOTS.release()


def initialize():
    if len(TOKEN) < 32 or not valid_environment(ENVIRONMENT):
        raise RuntimeError('sandbox_configuration_missing')
    if not Path(POLICY).is_file() or not ROOT.is_dir():
        raise RuntimeError('sandbox_image_incomplete')
    # The outer OCI proc has masked children. A fresh proc in this dedicated VM
    # allows an unprivileged child to mount its own PID-namespace proc safely.
    command(['/bin/mount', '-t', 'proc', '-o', 'nosuid,nodev,noexec', 'proc', '/proc'])
    # A dedicated Linux execution VM owns this cgroup subtree. Never run on an API host.
    controller = Path('/sys/fs/cgroup/zeus-controller')
    controller.mkdir(exist_ok=True)
    (controller / 'cgroup.procs').write_text(str(os.getpid()))
    Path('/sys/fs/cgroup/cgroup.subtree_control').write_text('+cpu +memory +pids')
    CGROUP.mkdir(exist_ok=True)
    (CGROUP / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    JOBS.mkdir(mode=0o711, exist_ok=True)
    JOBS.chmod(0o711)
    STATE.mkdir(mode=0o700, exist_ok=True)
    for group in CGROUP.iterdir():
        if group.is_dir():
            kill_group(group)
            group.rmdir()
    for directory in JOBS.iterdir():
        if directory.is_dir():
            if os.path.ismount(directory):
                command(['/bin/umount', str(directory)])
            directory.rmdir()


if __name__ == '__main__':
    initialize()
    ThreadingHTTPServer(('0.0.0.0', 8090), Handler).serve_forever()
