# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An OpenVPN auth plugin (`vpynauth.so`) written in C that embeds CPython and delegates
`auth-user-pass-verify` decisions to a Python module. The README describes it as alpha and
says it was tested only on Ubuntu 22.04. The author has since moved to WireGuard, so the repo
is kept as a starting point and isn't actively developed.

## Build

```sh
make            # builds vpynauth.so in the repo root
make clean      # removes src/*.o
make distclean  # also removes vpynauth.so
```

- Requires `python3-config` (python3-dev) and `/usr/include/openvpn/openvpn-plugin.h` (from
  the Debian/Ubuntu `openvpn` package).
- Compiler and linker flags come from `python3-config --cflags` / `--embed --libs`, so the
  `.so` is tied to the Python version present at build time. After a Python upgrade, run
  `make distclean && make`, because a plain `make` won't notice the change.
- `make test` runs `test/run.sh`, an end-to-end test that needs no root. It starts a real
  OpenVPN server with the plugin and `sample/vpyn.py`, then connects real clients. Everything
  runs inside `unshare --map-root-user --net`, with a throwaway PKI in a temp directory.
  - Set `KEEP=1` to keep the logs.
  - It needs `openvpn`, `openssl`, unprivileged user namespaces and `/dev/net/tun`.
  - There is no linter and there are no unit tests.

## Usage

```
plugin /path/to/vpynauth.so <script_dir> [module_name]
```

`script_dir` is appended to `sys.path`. `module_name` is imported, without the `.py`, and
defaults to `vpynauth`.

## Architecture (src/vpynauth.c)

- **`openvpn_plugin_open_v3`** registers only `OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY`.
  OpenVPN loads plugins with `RTLD_LOCAL`, which hides libpython's symbols from Python C
  extensions. To fix that, `open_v3` finds the libpython it is linked against with `dladdr`
  and re-`dlopen`s it with `RTLD_NOLOAD | RTLD_GLOBAL`. It then initializes Python, imports
  the module, and instantiates its `Verify` class once with no arguments.
- **`openvpn_plugin_func_v1`** turns the OpenVPN `envp` into a dict and calls
  `Verify().auth(vars)` with it. Bytes that aren't valid UTF-8 are decoded with
  `surrogateescape`. The call is synchronous; there is no deferred auth.
  - Only an exact `int` `0` or `True` accepts.
  - Anything else rejects: `False`, `None`, other ints, or a raised exception, which is
    printed with `PyErr_Print`.
- **`openvpn_plugin_close_v1`** releases the instance and removes the module from
  `sys.modules`. It deliberately does **not** call `Py_FinalizeEx`.
  - On SIGHUP, OpenVPN closes and reopens its plugins.
  - Restarting Python makes C extensions such as `_hashlib` segfault when they are imported
    again.
  - So Python, and the global `dlopen` of libpython, live for the whole process, and a reload
    re-imports the script.
  - `test/run.sh` covers this case.

### The Python contract

README.md documents the contract for users. When you change `func_v1`, update the README
to match.

## sample/

- `vpyn.py` is the reference module. It reads `users` from its own directory, not from
  OpenVPN's working directory. It also requires the client cert's `common_name` to equal the
  username.
- Each line of `users` is `username,scrypt$n$r$p$salt_hex$key_hex`. The `test` user's
  password is `test`.
- `adduser <name>` imports `hash_password` and `load_users` from `vpyn.py`, so the hash format
  is defined only in `vpyn.py`. Running `adduser` leaves a `sample/__pycache__/` behind; it's
  gitignored.
