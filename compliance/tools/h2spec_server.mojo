# Compliance tool: generic HTTP/2 server target for h2spec.
#
# Responds "200 + small body" to every complete request; protocol errors
# are signaled by Http2Connection itself (GOAWAY/RST with proper codes).
# h2spec opens one connection per test; connections are served
# sequentially, errors drop the connection and the loop accepts the next.
#
# Usage: h2spec_server [cert_pem key_pem]
# Prints "PORT <n>" and serves forever, with TLS when certificate paths
# are provided.

from std.ffi import c_int, external_call
from std.sys import CompilationTarget
from std.sys import argv

from h2 import H2TLSContext, Http2Connection
from hpack import HeaderField
from net import IOStream, TCPStream, TCPListener, is_timeout_error


def hf(name: StringSpan, value: StringSpan) -> HeaderField:
    return HeaderField(name=String(name), value=String(value))


def serve_connection[S: IOStream](mut conn: Http2Connection[S]) raises:
    var responded = List[UInt32]()
    while True:
        conn.process_next_frame()
        # Drain the incoming burst before responding (50ms inter-frame
        # lull = burst over), so a HEADERS flood is admitted/refused
        # against the concurrency limit before responses close earlier
        # streams. h2spec writes whole frames, so a timeout mid-frame
        # (which would desync) cannot happen here.
        conn.stream.set_read_timeout(50_000_000)
        try:
            while True:
                conn.process_next_frame()
        except e:
            if not is_timeout_error(e):
                raise e
        conn.stream.set_read_timeout(0)
        var ids = conn.stream_ids.copy()
        for sid in ids:
            var done = False
            for r in responded:
                if r == sid:
                    done = True
            if done:
                continue
            if conn.streams[sid].reset_code:
                responded.append(sid)
                continue
            if conn.streams[sid].headers_done and conn.streams[sid].end_stream:
                responded.append(sid)
                var headers = [
                    hf(":status", "200"),
                    hf("content-type", "text/plain"),
                ]
                conn.send_headers(sid, Span(headers), end_stream=False)
                var body = String("hello h2spec")
                conn.send_data(sid, body.as_bytes(), end_stream=True)


def main() raises:
    var args = argv()
    var listener = TCPListener("127.0.0.1", 0)
    print("PORT ", listener.local_port, sep="")
    # Reap children automatically (SIG_IGN for SIGCHLD).
    var sigchld: c_int
    comptime if CompilationTarget.is_macos():
        sigchld = 20
    else:
        sigchld = 17
    _ = external_call["signal", Int](sigchld, Int(1))
    while True:
        var tcp = listener.accept()
        # h2spec keeps multiple connections open concurrently (a held-open
        # probe plus the test connection); fork a child per connection so
        # a silent one can't starve the rest. Mojo has no threads yet
        # (PRIMITIVES.md #7) — fork(2) is the test-tool workaround.
        var pid = external_call["fork", c_int]()
        if pid == 0:
            listener.close()
            try:
                if len(args) > 1:
                    var context = H2TLSContext.server(
                        String(args[1]), String(args[2])
                    )
                    var conn = context.accept(tcp^)
                    try:
                        serve_connection(conn)
                    except:
                        conn.close()
                else:
                    var conn = Http2Connection(tcp^, is_client=False)
                    try:
                        serve_connection(conn)
                    except:
                        conn.close()
            except:
                pass
            external_call["_exit", NoneType](c_int(0))
        else:
            tcp.close()
