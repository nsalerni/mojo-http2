# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""HTTP/2 over TLS with mandatory `h2` ALPN negotiation.

`H2TLSContext` configures mojo-tls with the single protocol token allowed
for HTTP/2 over TLS. Its client and server handshakes return the same
`Http2Connection` state machine used for cleartext h2c, specialized over
`TLSStream` through mojo-net's `IOStream` trait.
"""

from net import TCPStream
from tls import TLSContext, TLSStream

from .connection import Http2Connection


comptime H2_ALPN = "h2"
"""The ALPN protocol identifier for HTTP/2 over TLS."""


@fieldwise_init
struct H2TLSContext(Movable):
    """Reusable TLS configuration that permits only HTTP/2.

    Create a role-specific context with `client()` or `server()`, then
    wrap each connected `TCPStream` with `connect()` or `accept()`.
    Successful methods return a ready HTTP/2 connection over TLS.
    """

    var _tls: TLSContext
    var _is_server: Bool

    @staticmethod
    def client(
        *, verify: Bool = True, ca_file: StringSpan = ""
    ) raises -> H2TLSContext:
        """Builds a client context that offers only the `h2` ALPN token.

        Args:
            verify: Verify the server certificate chain and hostname.
                Disable only in controlled tests.
            ca_file: Path to a PEM trust bundle; empty uses the system
                trust store.

        Returns:
            A reusable client-side HTTP/2 TLS context.

        Raises:
            If the TLS context or trust store cannot be initialized.
        """
        return H2TLSContext(
            _tls=TLSContext.client(
                verify=verify, ca_file=String(ca_file), alpn=[String(H2_ALPN)]
            ),
            _is_server=False,
        )

    @staticmethod
    def server(
        cert_chain_pem: StringSpan, key_pem: StringSpan
    ) raises -> H2TLSContext:
        """Builds a server context that accepts only the `h2` token.

        Args:
            cert_chain_pem: Path to the PEM certificate chain.
            key_pem: Path to the matching PEM private key.

        Returns:
            A reusable server-side HTTP/2 TLS context.

        Raises:
            If the TLS context, certificate, or key cannot be loaded.
        """
        return H2TLSContext(
            _tls=TLSContext.server(
                String(cert_chain_pem), String(key_pem), alpn=[String(H2_ALPN)]
            ),
            _is_server=True,
        )

    def connect(
        self, var tcp: TCPStream, server_name: StringSpan
    ) raises -> Http2Connection[TLSStream]:
        """Runs a client handshake and starts HTTP/2 over the TLS stream.

        Args:
            tcp: A connected TCP stream; ownership is taken.
            server_name: Hostname used for SNI and certificate checking.

        Returns:
            A client-role HTTP/2 connection over the negotiated TLS stream.

        Raises:
            If used with a server context, the TLS handshake fails, or the
            peer does not select `h2` with ALPN.
        """
        if self._is_server:
            raise Error("h2: client connect called on a server TLS context")
        var stream = self._tls.connect(tcp^, server_name)
        var selected = stream.negotiated_alpn()
        if selected != H2_ALPN:
            stream.close()
            raise Error(
                "h2: TLS peer did not negotiate the required h2 ALPN token"
            )
        return Http2Connection(stream^, is_client=True)

    def accept(self, var tcp: TCPStream) raises -> Http2Connection[TLSStream]:
        """Runs a server handshake and starts HTTP/2 over the TLS stream.

        Args:
            tcp: An accepted TCP stream; ownership is taken.

        Returns:
            A server-role HTTP/2 connection over the negotiated TLS stream.

        Raises:
            If used with a client context, the TLS handshake fails, or the
            peer does not select `h2` with ALPN.
        """
        if not self._is_server:
            raise Error("h2: server accept called on a client TLS context")
        var stream = self._tls.accept(tcp^)
        var selected = stream.negotiated_alpn()
        if selected != H2_ALPN:
            stream.close()
            raise Error(
                "h2: TLS peer did not negotiate the required h2 ALPN token"
            )
        return Http2Connection(stream^, is_client=False)
