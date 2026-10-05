"""Egress control for product JVMs (Linux container only).

* All outbound TCP of the `mc` user to non-loopback destinations is redirected to
  the interposer, regardless of port. DNS (UDP/TCP 53) stays direct so reverse-DNS
  signals behave as in production.
* `mc` cannot reach the interposer control port or the orchestrator.
* The throwaway CA is added to the container JDK trust store.
"""
import os
import subprocess

from .interposer import CATCH_ALL_PORT, CONTROL_PORT

MC_UID = 1001


def run(*command):
    subprocess.run(command, check=True)


def install(ca_pem):
    for tool, loopback in (('iptables', '127.0.0.0/8'), ('ip6tables', '::1/128')):
        run(tool, '-t', 'nat', '-F', 'OUTPUT')
        run(tool, '-t', 'nat', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', str(MC_UID), '-p', 'tcp',
            '!', '-d', loopback, '!', '--dport', '53', '-j', 'REDIRECT', '--to-ports', str(CATCH_ALL_PORT))
        run(tool, '-F', 'OUTPUT')
        run(tool, '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', str(MC_UID), '-p', 'tcp', '-d', loopback,
            '--dport', str(CONTROL_PORT), '-j', 'REJECT')
    java_home = os.environ.get('JAVA_HOME', '/opt/java/openjdk')
    subprocess.run([os.path.join(java_home, 'bin', 'keytool'), '-delete', '-cacerts', '-storepass', 'changeit',
                    '-alias', 'mc-antivpn-bench'], capture_output=True)
    run(os.path.join(java_home, 'bin', 'keytool'), '-importcert', '-noprompt', '-cacerts', '-storepass', 'changeit',
        '-alias', 'mc-antivpn-bench', '-file', ca_pem)


def block_port(port, mode):
    """mode: 'refuse' (RST) or 'blackhole' (silently drop) for mc->loopback:port; 'clear' removes it."""
    for tool, loopback in (('iptables', '127.0.0.1'), ('ip6tables', '::1')):
        for target in (['REJECT', '--reject-with', 'tcp-reset'], ['DROP']):
            while subprocess.run([tool, '-D', 'OUTPUT', '-m', 'owner', '--uid-owner', str(MC_UID), '-p', 'tcp',
                                  '-d', loopback, '--dport', str(port), '-j', *target],
                                 capture_output=True).returncode == 0:
                pass
        if mode == 'refuse':
            run(tool, '-I', 'OUTPUT', '-m', 'owner', '--uid-owner', str(MC_UID), '-p', 'tcp', '-d', loopback,
                '--dport', str(port), '-j', 'REJECT', '--reject-with', 'tcp-reset')
        elif mode == 'blackhole':
            run(tool, '-I', 'OUTPUT', '-m', 'owner', '--uid-owner', str(MC_UID), '-p', 'tcp', '-d', loopback,
                '--dport', str(port), '-j', 'DROP')
