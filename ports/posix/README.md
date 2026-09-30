# POSIX reference port

`lxp_port_posix.c` implements LXP's network provider (`lxp_net_ops_t`) over the host's BSD
sockets, plus a synthetic network interface for the `SIOC*` ioctls. It is what a standalone
build compiles with `-DLXP_PORT_POSIX=ON`, and what the host unit tests and fuzzers link to
exercise the socket layer and the 9P client against real sockets.

It is not an RTOS port. It supplies no `lxp_os_ops_t` and runs no ARM guest: the process
model runs on target, and `ports/qemu-mps2` is the reference for that. The clock and cache
hooks the host tests need come from `tests/stub_lnx_run.c`.

## What it provides

| Entry point | Declared in | Provides |
|---|---|---|
| `lxp_posix_net_ops()` | `include/lxp/ports/posix.h` | The immutable `lxp_net_ops_t`: TCP and UDP sockets, blocking with timeouts, non-blocking mode, `poll`, `shutdown`, name queries. |
| `lxp_posix_netif()` | `include/lxp/ports/posix.h` | A synthetic `eth0` for `ifconfig`-style ioctls: loopback 127.0.0.1/8 and up, with a fixed MAC; the setters change it in memory. |

Socket handles come from a fixed pool of `LXP_NSOCK` entries, plus one for the 9P client when
netfs is built, emptied at `run_begin` and `run_end`. Host `errno` values are translated to
`lxp_err_t` in one function, `to_lxp_err()`; the core turns them into guest errnos through its
own table.

## Using it

```sh
cmake -S . -B build -DLXP_PORT_POSIX=ON -DLXP_ENABLE_NET=ON
cmake --build build
```

Link `lxp::lxp` and pass `lxp_posix_net_ops()` as the `net` member of the `lxp_providers_t`
handed to `lxp_run()`, with `lxp_posix_netif()` as the run configuration's `netif`. An embedding
on a real RTOS supplies its own network provider instead; this one is the reference for the
contract in `include/lxp/lxp_net_ops.h`.

## Tests that use it

- `lxp_test_stub` (`tests/`): the socket, netfs and syscall suites.
- `lxp_coord_test` (`tests/`): coordinator suites that cross lifecycle work with socket waits.
- The fuzz harnesses (`fuzz/`), for the 9P and syscall parsers.
