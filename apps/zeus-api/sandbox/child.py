"""Trusted launcher: join the allocated cgroup before executing bubblewrap."""
import os
import sys
from pathlib import Path

if __name__ == '__main__':
    group, root, work, temporary, script, policy = sys.argv[1:]
    Path(group, 'cgroup.procs').write_text(str(os.getpid()))
    fd = os.open(policy, os.O_RDONLY)
    os.set_inheritable(fd, True)
    args = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--uid', '10001', '--gid', '10001', '--cap-drop', 'ALL',
            '--ro-bind', root, '/', '--proc', '/proc', '--dev', '/dev',
            '--bind', work, '/workspace', '--bind', temporary, '/tmp',
            '--ro-bind', script, '/run/zeus-script', '--chdir', '/workspace',
            '--clearenv', '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin',
            '--setenv', 'HOME', '/tmp', '--setenv', 'TMPDIR', '/tmp',
            '--setenv', 'CARGO_HOME', '/tmp/cargo', '--setenv', 'PYTHONNOUSERSITE', '1',
            '--setenv', 'GIT_CONFIG_NOSYSTEM', '1', '--setenv', 'GIT_CONFIG_GLOBAL', '/dev/null',
            '--seccomp', str(fd), '/bin/sh', '/run/zeus-script']
    os.setgroups([])
    os.setgid(10001)
    os.setuid(10001)
    os.execve(args[0], args, {'PATH': '/usr/bin:/bin'})
