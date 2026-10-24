quicly [![CI](https://github.com/h2o/quicly/actions/workflows/ci.yml/badge.svg)](https://github.com/h2o/quicly/actions/workflows/ci.yml)
===

Quicly is an IETF [QUIC](https://quicwg.github.io/) protocol implementation, written from the ground up to be used primarily within the H2O HTTP server.

The software is licensed under the MIT License.

Flexicast
---

This branch provides an experimental DATAGRAM-only Flexicast primitive and unicast control-frame callbacks based on
[draft-navarre-quic-flexicast-03](https://www.ietf.org/archive/id/draft-navarre-quic-flexicast-03.html).
Draft 03 names FC_STATE action `0x03` `LISTEN`; `QUICLY_FLEXICAST_STATE_LISTEN` is the current API name, and
`QUICLY_FLEXICAST_STATE_READY` remains an alias for existing draft 02 callers. The action's wire encoding is unchanged.

Enable Multipath and the appropriate `transport_params.flexicast_support` address families on both peers. The application
handles flow registration, control-frame sequence ordering, address-family selection, JOIN/LISTEN/LEAVE transitions, multicast socket membership,
and independently generated traffic secrets. Control frames are restricted to their permitted endpoint roles and 1-RTT
packets. Rekeying retains cumulative member measurements but requires packet numbers to keep increasing so delayed ACKs
cannot acknowledge packets from a new key epoch. PATH_ACK uses the negotiated QUIC ACK-delay encoding on the wire;
`receive_flexicast_ack` supplies the delay in milliseconds to the flow feedback API.
Pending feedback reports the newest 64 receive ranges and retains them for repetition in later ACKs. Queued and
retransmitted PATH_ACK frames include elapsed receiver delay so multicast RTT estimation can account for unicast
queueing and retransmission. The configured ACK delay controls when feedback becomes due, rather than capping the reported delay.

Use `quicly_flexicast_receive_datagrams_at` to receive all DATAGRAM frames in a packet without copying their payloads.
The singular receive API remains available for packets containing at most one DATAGRAM; it returns
`QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL` for multiple DATAGRAMs without consuming the packet number. Both APIs decrypt
in place, so retrying requires a fresh encrypted copy. PADDING and PING are accepted; a packet containing no DATAGRAM
returns zero payloads (or a null payload pointer from the singular API). Pass authenticated protocol/frame errors and
`QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED` to `quicly_flexicast_handle_receive_error` with the associated unicast connection.
Unauthenticated packet errors do not close that connection.

Outgoing protected packets default to a maximum of 1200 bytes. Set `max_packet_size` only to a size supported by the path
and all receivers, up to 65507 bytes. Applications must also negotiate DATAGRAM support and enforce every receiver's
`max_datagram_frame_size`, and use the congestion controller's rate and burst outputs to pace physical transmission.
These requirements also apply when one protected packet is replicated to several unicast destinations.

Cryptographic limits are enforced for each installed traffic secret, including after reinstalling a previous secret.
AES-GCM permits at most 2^23 encrypted packets per secret; reaching the limit returns
`QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED` before consuming another packet number. Install a fresh secret through the
application's FC_KEY lifecycle to resume. Failed authentications accumulate across rekeys; exhausting that budget is
terminal for the flow. Configuration may lower these limits but cannot raise them. Rekeying suspends delivery membership
and congestion-control participation until each receiver is attached again; built-in controllers retain learned path
history without letting inactive receivers limit the rate.

The draft still leaves frame and error code assignments and some wire details unspecified. This implementation retains
provisional FC frame types `0x173e00`–`0x173e02`, transport parameter `0xedf3` with one octet per address-family boolean,
and the standard QUIC protocol-violation error for FC protocol violations. Its shared-packet format remains private:
eight-byte numeric flow IDs occupy a namespace above the unicast path-ID limit. These choices do not establish
interoperability with other Flexicast implementations or provide multicast STREAM reliability.

How to build
---

```
% git submodule update --init --recursive
% cmake .
% make
```

Building the software requires OpenSSL 1.0.2 or above.
If you have OpenSSL installed in a non-standard directory, you can pass the location using the `PKG_CONFIG_PATH` environment variable.

```
% PKG_CONFIG_PATH=/path/to/openssl/lib/pkgconfig cmake .
```

How to test
---

Install dependencies first:

```
# If you use system perl, use --sudo
% curl -sL https://cpanmin.us | perl - --sudo --self-upgrade
% cpanm --installdeps --notest --sudo .

# Otherwise, you'd better omit --sudo
% curl -sL https://cpanmin.us | perl - --self-upgrade
% cpanm --installdeps --notest .
```

Then, run the tests:
```
% make check
```

Running quicly
---

A command-line program (named `cli`) that runs either as a server or a client `cli` is provided.

To run the command as a client, specify the peer hostname and port number as the arguments.

```
% ./cli host port
```

To run the command as a server, specify the files that contain the certificate and private key, as well as the hostname and the port number to which the server should bind.

```
% ./cli -c server.crt -k server.key 0.0.0.0 4433
```

For more options, please refer to `./cli --help`.
