"""Test-only HTTP/HTTPS proxy through the real guest fixture.

No responses are replaced: HTTP requests or CONNECT TLS bytes pass over SSH
to netcat inside nqrclient. Run router-guest-client.sh setup first. Password is read by
router.Connection from the environment/prompt, never from this file.
"""
import argparse
import select
import socketserver
import router
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='192.168.8.1')
    parser.add_argument('--user', default='root')
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--listen-port', type=int, default=51255)
    args = parser.parse_args()
    with router.Connection(args) as connection:
        transport = connection.client.get_transport()

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(20)
                header = b''
                while b'\r\n\r\n' not in header and len(header) < 4096:
                    chunk = self.request.recv(1024)
                    if not chunk:
                        return
                    header += chunk
                first, _, rest = header.partition(b'\r\n')
                parts = first.split(b' ')
                tunnel = len(parts)==3 and parts[0]==b'CONNECT' and parts[1]==b'192.168.9.1:2051'
                plain = False
                if len(parts)==3 and parts[0] in (b'GET',b'HEAD',b'POST'):
                    address=urlsplit(parts[1].decode('ascii'))
                    plain=address.scheme=='http' and address.hostname=='192.168.9.1' and address.port==2050
                if not tunnel and not plain:
                    self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                    return
                channel = transport.open_session(timeout=20)
                try:
                    channel.exec_command('ip netns exec nqrclient nc 192.168.9.1 '+('2051' if tunnel else '2050'))
                    if tunnel:
                        self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    else:
                        head, _, body = rest.partition(b'\r\n\r\n')
                        fields=[line for line in head.split(b'\r\n') if not line.lower().startswith((b'connection:',b'proxy-connection:'))]
                        target=(address.path or '/')+('?' + address.query if address.query else '')
                        channel.sendall(parts[0]+b' '+target.encode('ascii')+b' '+parts[2]+b'\r\n'+b'\r\n'.join(fields)+b'\r\nConnection: close\r\n\r\n'+body)
                    self.request.settimeout(None)
                    while transport.is_active():
                        ready, _, _ = select.select([self.request, channel], [], [], 30)
                        if not ready:
                            break
                        if self.request in ready:
                            data = self.request.recv(65536)
                            if not data:
                                break
                            channel.sendall(data)
                        if channel in ready:
                            data = channel.recv(65536)
                            if not data:
                                break
                            self.request.sendall(data)
                except (OSError, EOFError):
                    pass
                finally:
                    channel.close()

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        with Server(('127.0.0.1', args.listen_port), Handler) as server:
            print(f'Guest HTTP/HTTPS proxy listening on 127.0.0.1:{args.listen_port}', flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == '__main__':
    main()
