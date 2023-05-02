import http.server
from urllib import parse
import http
import argparse

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        query = parse.urlparse(self.path).query
        query_components = dict(qc.split("=") for qc in query.split("&"))
        size = int(query_components['bytes'])
        self.send_response(200)
        self.send_header('Content-length', size)
        self.end_headers()
        chunk = 1024 * 4
        for _ in range(size // chunk):
            self.wfile.write(b'S' * chunk)
        self.wfile.write(b'S' * (size % chunk))
        return

    def do_POST(self):
        CHUNK = 1024
        size = 0
        content = int(self.headers['Content-Length'])
        while size < content:
            self.rfile.read(CHUNK if CHUNK < content - size else content - size)
            size += CHUNK
            pass
        self.send_response(http.HTTPStatus.OK)
        self.send_header('Content-length', 2)
        self.end_headers()
        self.wfile.write(b'ok')
        return


def serve_forever():
    # Verify arguments in case the method was called directly
    assert hasattr(args, 'port') and type(args.port) is int
    handler_class = SimpleHTTPRequestHandler
    http.server.test(
        HandlerClass=handler_class,
        port=args.port,
        bind='0.0.0.0',
    )


def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument('port', type=int, default=80, nargs='?',
                        help='Specify alternate port [default: 80]')

    args = parser.parse_args()
    serve_forever()


main()
