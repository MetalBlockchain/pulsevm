# State-history session lifetime

The WebSocket session future owns both its socket writer and optional block
producer through task guards that abort on drop. No task handle may detach
when a request fails to parse, the peer disconnects, or the session future is
cancelled. This ownership applies even if the caller keeps the `Session`
object after cancelling `start`.

Replacing a get-blocks request aborts and joins the previous producer before
resetting the acknowledgement window. A producer waiting for an unavailable
block or for acknowledgement credit has the same lifetime as the session;
there is no separate watch channel whose closure could be mistaken for an
instruction to continue.

Normal closure stops the producer and allows the writer to drain. Socket
writes and the final drain have a ten-second timeout so a peer that stops
reading cannot retain the writer indefinitely. Writer completion also ends
the input loop. Error returns and cancellation abort both tasks immediately
(the runtime releases their resources when it next polls the cancelled tasks).

This changes connection resource management only. SHiP request/response
serialization and consensus execution are unchanged; no protocol activation
or coordinated chain upgrade is required.

The regression drives the real WebSocket handshake and message loop over
in-memory duplex I/O. It covers unknown and truncated requests, empty frames,
normal close, abrupt disconnect, stream replacement and cancellation while
the `Session` remains alive. A pong provides a processing barrier before each
termination, and controller ownership proves the producer has released its
resources. Cleanup-test timeouts are deadlock guards, not timing-based success
criteria. A separate paused-clock test checks the socket-write deadline while
the peer keeps its connection open without reading the ABI.
