# Bug fixes and validation

## Fixed

- HTTP request parsing: malformed request lines could dereference NULL; header
  values could overwrite fixed-size fields; substring and case-sensitive header
  matching misidentified headers; positive BAD_REQ errors were ignored by the
  caller. Header names now match exactly and case-insensitively, field copies
  are bounded, and invalid input propagates as BAD_REQ.
- Framing: Content-Length accepted negative numbers/trailing garbage, duplicate
  lengths were not tracked, and Transfer-Encoding could bypass validation.
  Lengths are validated and bounded; unsupported Transfer-Encoding is rejected.
- Request buffering: header scanning read beyond supplied buffers; raw validation
  advanced the owning allocation pointer; large bodies were copied into the
  fixed buffer despite allocation; growth used capacity as received length.
  HTTP and TLS now retain fragmented input, track capacity separately, copy
  binary bodies by length, and wait for the declared body before processing.
- JSON: valid arrays starting with numbers/literals failed; nested-array comma
  state used the wrong parent; missing separators/multiple roots could pass;
  truncated input could read past its end; exact token/depth limits failed;
  token fields depended on zero-initialized output. Added boundary/state checks.
- JSON escapes: plain and escaped writes could exceed destination capacity,
  larger destinations were wrongly rejected, truncated/unknown escapes were
  mishandled, and malformed hexadecimal input was accepted. Added bounded
  decoding, strict hex validation, and surrogate-pair UTF-8 encoding.
- Responses: string copies and strlen truncated binary content. HTTP writes now
  track partial progress without changing socket blocking mode; TLS retries own
  a binary buffer and retain its explicit length after the caller frees its
  response. TLS request handling uses the same bounded reader for every phase.
- Error/preflight responses: corrected Content-Length spelling, supplied the
  advertised 400 body, fixed 500 fallthrough/NULL dereference, terminated OPTIONS
  headers, framed 404 bodies, excluded a fallback page's trailing NUL, and
  prevented stale header suffixes. HEAD suppresses the response body.
- Standalone dispatch: plain HTTP accepted on the disabled secondary descriptor
  and attempted to parse the request before passing its socket to the worker.
  It now accepts on the active listener and leaves reading to the worker.
  Standalone static serving includes binary resources; HEAD follows GET routing.
- Error cleanup: initialized HTTP response storage before the bad-request jump;
  avoided signalling process ID -1 in main's worker-startup failures.
- Build/tests: default make target and missing object directories prevented a
  clean standalone build, OWN_DB was unconditionally enabled, and incremental
  links used only changed objects. Added independent DB objects, header dependency
  tracking, a sanitizer-backed test target, and fixed the existing Unicode test's
  out-of-bounds index and failure reporting.

## Validation performed

- Reproduced the original malformed-request NULL dereference under ASan/UBSan;
  reproduced valid-JSON rejection and embedded-NUL response corruption.
- Clean standalone build and regression suite with AddressSanitizer and
  UndefinedBehaviorSanitizer. Leak detection was disabled because this execution
  environment prevents LeakSanitizer from inspecting processes.
- Existing JSON examples and Unicode boundary cases, plus new malformed-input,
  exact-capacity/depth, large-body, binary-body, and escape-decoder tests.
- Nonblocking socket-pair tests: byte-at-a-time headers, fragmented 9,000-byte
  bodies, and 100,000-byte responses with forced partial writes.
- Local TLS client/server tests: handshake, fragmented binary input, forced output
  retries, and freeing the caller's response while TLS output is pending.
- 5,000 deterministic generated/mutated JSON cases compared with Python's JSON
  parser (restricting successful roots to objects/arrays).

## Boundaries

This is not a claim that the repository is free of all bugs. The standalone
server compiles, but a full process-to-process server smoke test could not finish:
this environment returned EPERM from the worker Unix-socket connect operation.
The socket-pair HTTP/TLS component tests did complete. The separate database
implementation/headers are absent, so the OWN_DB build and database integration
were not validated. Production certificate configuration, the outbound HTTP/DNS
client, and concurrency/load behavior need separate review. Existing warnings
remain in code outside the tested paths.

## Second pass: event monitoring, Unix sockets, and static files

This follow-up commit is based on the first fix commit (`bdadb7b`).

- Replaced positive EINTR monitor results with `MONITOR_INTERRUPTED` (-2), updating
  all monitor callers. On Linux EINTR is 4, so the old API made callers discard
  batches containing exactly four ready descriptors.
- Fixed epoll descriptor leaks when starting a new monitor, cleanup after failed
  registration, and repeated shutdown closing an unrelated reused descriptor.
  Registering an already-monitored descriptor now updates its requested events.
- Unix socket paths are validated before copying. Socket flags now actually enable
  nonblocking mode and close-on-exec. Failed connect/bind/listen calls close their
  descriptors while preserving errno. Listener setup refuses to unlink regular
  files or symlinks. An accept returning EAGAIN no longer tries to register fd -1.
- Static-file resolution strips query strings and decodes percent escapes before
  checking path components, rejecting malformed escapes, NULs, traversal, and
  symlinks. Special files are opened nonblocking and rejected unless regular,
  preventing FIFO requests from hanging. File reads handle EINTR and short reads.

The new `tests/infrastructure.c` reproduces the former interruption result,
nonblocking-flag error, and query-string lookup failure. Tests cover four ready
sockets, interrupted waits, monitor replacement/repeated cleanup, long socket
paths, failed-socket cleanup, preservation of regular files, decoded traversal,
query/encoded filenames, symlinks, FIFOs, and interrupted/short file reads. The
complete test suite passes with ASan/UBSan (leak detection disabled as above).
Unix SOCK_SEQPACKET setup remains blocked by the execution environment, so Unix
transport tests substitute socket/bind/listen/connect/accept4 calls with controlled
results and real socket-pair descriptors; they are not an end-to-end IPC test.
File tests isolate their document root in a temporary directory using a test-only
getuid wrapper. A read wrapper forces interrupted/short reads deterministically.
