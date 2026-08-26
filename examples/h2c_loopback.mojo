# Incremental h2c request and response between two in-process endpoints.

from h2 import Http2Connection
from hpack import HeaderField
from net import IOStream


struct LoopbackStream(IOStream):
    """A transport placeholder for the feed and drain connection API."""

    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("loopback example does not perform blocking reads")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data
        raise Error("loopback example does not perform blocking writes")

    def write_some(self, data: Span[Byte, _]) raises -> Int:
        self.write_all(data)
        return len(data)

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


def require(condition: Bool, message: String) raises:
    if not condition:
        raise Error(message)


def drain_to_peer(
    mut source: Http2Connection[LoopbackStream],
    mut target: Http2Connection[LoopbackStream],
    chunk_size: Int,
) raises -> Int:
    var wire = source.take_pending_output()
    var offset = 0
    while offset < len(wire):
        var end = min(offset + chunk_size, len(wire))
        # Readiness-driven transports may split a preface or frame anywhere.
        # feed_input retains the incomplete suffix until the next call.
        _ = target.feed_input(Span(wire)[offset:end])
        offset = end
    return len(wire)


def main() raises:
    var client = Http2Connection(LoopbackStream(), is_client=True)
    var server = Http2Connection(LoopbackStream(), is_client=False)

    # Construction queues client startup bytes. Each endpoint drains only
    # after feeding its peer, which also carries SETTINGS acknowledgements.
    _ = drain_to_peer(client, server, 5)
    _ = drain_to_peer(server, client, 3)
    _ = drain_to_peer(client, server, 2)
    require(client.peer_settings_received, "client did not receive SETTINGS")
    require(server.peer_settings_received, "server did not receive SETTINGS")
    print("h2c startup complete")

    var stream_id = client.open_stream()
    var request_headers = [
        HeaderField(":method", "POST"),
        HeaderField(":scheme", "http"),
        HeaderField(":path", "/example.Echo/Call"),
        HeaderField(":authority", "localhost"),
        HeaderField("content-type", "text/plain"),
    ]
    client.queue_headers(stream_id, Span(request_headers), end_stream=False)
    var request = String("hello from the incremental client")
    var request_bytes = request.as_bytes()
    var request_consumed = client.queue_data(
        stream_id, request_bytes, end_stream=True
    )
    require(
        request_consumed == len(request_bytes),
        "request did not fit available flow-control credit",
    )
    _ = drain_to_peer(client, server, 7)

    require(server.streams[stream_id].headers_done, "request headers missing")
    require(server.streams[stream_id].end_stream, "request did not end")
    var received_request = server.take_buffered_data(
        stream_id, len(request_bytes)
    )
    require(
        String(from_utf8=received_request) == request,
        "request body changed in transit",
    )
    print("server received: " + String(from_utf8=received_request))

    var response_headers = [
        HeaderField(":status", "200"),
        HeaderField("content-type", "text/plain"),
    ]
    server.queue_headers(stream_id, Span(response_headers), end_stream=False)
    var response = String("hello from the incremental server")
    var response_bytes = response.as_bytes()
    var response_consumed = server.queue_data(
        stream_id, response_bytes, end_stream=True
    )
    require(
        response_consumed == len(response_bytes),
        "response did not fit available flow-control credit",
    )
    _ = drain_to_peer(server, client, 4)

    require(client.streams[stream_id].headers_done, "response headers missing")
    require(client.streams[stream_id].end_stream, "response did not end")
    var received_response = client.take_buffered_data(
        stream_id, len(response_bytes)
    )
    require(
        String(from_utf8=received_response) == response,
        "response body changed in transit",
    )
    _ = drain_to_peer(client, server, 6)
    print("client received: " + String(from_utf8=received_response))
