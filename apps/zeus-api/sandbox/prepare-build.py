"""Download signed Alpine packages on the host; apk resolves/verifies inside Alpine.
Used only by scripts/container build sandbox. No repository credentials involved.
"""
import concurrent.futures
import pathlib
import platform
import subprocess
import sys
import shutil
import urllib.request

root = pathlib.Path(sys.argv[1]).resolve()
arch = 'aarch64' if platform.machine() == 'arm64' else 'x86_64'
base = 'docker.io/library/alpine:3.24.1'
packages = ['busybox', 'ca-certificates', 'git', 'nodejs', 'npm', 'pnpm', 'python3', 'py3-pip',
            'rust', 'cargo', 'build-base', 'bash', 'bubblewrap', 'util-linux', 'libseccomp-dev']
cache = pathlib.Path(__file__).resolve().parents[3] / '.zeus' / 'sandbox-apk-cache'
cache.mkdir(exist_ok=True)
for repo in ('main', 'community'):
    directory = cache / repo / arch
    directory.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(f'https://dl-cdn.alpinelinux.org/alpine/v3.24/{repo}/{arch}/APKINDEX.tar.gz', timeout=60) as response:
        (directory / 'APKINDEX.tar.gz').write_bytes(response.read())
(cache / 'repositories').write_text('file:///packages/main\nfile:///packages/community\n')
result = subprocess.run(['container', 'run', '--remove', '--volume', f'{cache}:/packages:ro', base,
    'apk', '--repositories-file', '/packages/repositories', 'fetch', '--recursive', '--url', '--simulate', *packages],
    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if result.returncode:
    raise SystemExit('Alpine dependency resolution failed: ' + result.stderr[-2000:])
urls = [line.strip() for line in result.stdout.splitlines() if line.startswith('file:///packages/') and line.endswith('.apk')]
if not urls:
    raise SystemExit('Alpine resolver returned no packages')
def download(source):
    relative = source.removeprefix('file:///packages/')
    target = cache / relative
    if target.exists():
        return
    with urllib.request.urlopen('https://dl-cdn.alpinelinux.org/alpine/v3.24/' + relative, timeout=120) as response:
        temporary = target.with_suffix('.download')
        temporary.write_bytes(response.read())
        temporary.replace(target)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    list(executor.map(download, urls))
shutil.copytree(cache, root / 'apk')
print(f'Prepared {len(urls)} signed Alpine packages for {arch}.')
