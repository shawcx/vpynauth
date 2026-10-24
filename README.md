*Pivoted to a WireGuard solution for my needs but leaving this here as a starting point for others.*

# vpynauth
OpenVPN Auth Plugin that calls a Python script

The original version was tested with OpenVPN on Ubuntu 22.04. The current version was tested
on Ubuntu 24.04 (Python 3.12) with a small program that loads the plugin the same way OpenVPN
does. It has not yet been run under a real OpenVPN server.

## Build

Needs the Python headers and OpenVPN's plugin header:

    sudo apt install python3-dev openvpn
    make

The plugin links against the Python that `python3-config` reports, so rebuild with
`make distclean && make` after a Python upgrade.

## Usage

In the OpenVPN server config:

    plugin /path/to/vpynauth.so /path/to/script_dir [module]

`script_dir` is added to `sys.path`, and `module` is imported from it. Give the module name
without `.py`. It defaults to `vpynauth`.

## Writing the Python module

The module must define a `Verify` class. OpenVPN creates one instance, with no arguments,
when it starts. Every login then calls its `auth` method with OpenVPN's environment as a
dict:

```python
class Verify:
    def auth(self, vars):
        # vars['username'], vars['password'], vars['common_name'], vars['untrusted_ip'], ...
        return 0  # accept
```

- Return `0` or `True` to accept. Any other return value (`False`, `None`, other numbers)
  rejects, and so does a raised exception.
- Values that aren't valid UTF-8 are decoded with `surrogateescape`.
  `value.encode('utf-8', 'surrogateescape')` gets the original bytes back.
- `auth` runs synchronously and blocks OpenVPN until it returns, so keep it fast.
- `print` output goes to OpenVPN's stdout. Pass `flush=True` so lines aren't held in a
  buffer.

## Sample

`sample/vpyn.py` is a working module. It checks passwords against the scrypt hashes in
`sample/users`. It also requires the client certificate's common name to match the
username.

Add users with:

    sample/adduser alice

The included `test` user's password is `test`. Remove that user before real use.

## Upgrading from the original version

These changes break scripts and data written for the original version:

- `auth` receives a dict. It used to receive a list of `KEY=VALUE` strings.
- Returning `False` now rejects. It used to accept, because `False == 0`.
- `sample/users` uses scrypt hashes instead of `crypt` hashes. Re-add existing users with
  `sample/adduser`.
- The sample reads `users` from its own directory. It used to read it from OpenVPN's
  working directory.
