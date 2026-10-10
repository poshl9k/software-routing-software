"""Pure pppd configuration generation; returned files contain plaintext secrets."""

from cryptography.fernet import InvalidToken

from ..secrets import decrypt_secret


def _word(value: str) -> str:
    """Quote a pppd options/secrets word, rejecting line and control injection."""
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("pppoe.invalid_credential")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def generate_pppoe(version, key: bytes) -> dict[str, str]:
    """Return peer files and a shared CHAP secrets file in stable name order."""
    files = {}
    secrets = []
    for interface in sorted(version.configuration.interfaces, key=lambda item: item.name):
        if interface.addressing != "pppoe":
            continue
        if not interface.pppoe_username or interface.pppoe_password is None:
            raise ValueError("pppoe.credentials_required")
        try:
            password = decrypt_secret(interface.pppoe_password, key)
        except (ValueError, InvalidToken, UnicodeError):
            raise ValueError("pppoe.secret_decryption_failed") from None
        username = _word(interface.pppoe_username)
        # pppd treats a secret beginning with @ as a path even if quoted.
        if password.startswith("@"):
            raise ValueError("pppoe.invalid_credential")
        password_word = _word(password)
        # pppd(8) PPPOE OPTIONS documents nic-interface and plugin pppoe.so;
        # Debian ppp 2.5.2 ships rp-pppoe.so as a symlink to pppoe.so.
        # pppd(8) AUTHENTICATION documents client server secret IP columns
        # and the distinct pap-secrets/chap-secrets files. Debian's example
        # peers-pppoe documents user/noauth/noipdefault/defaultroute/persist.
        # https://manpages.debian.org/trixie/ppp/pppd.8.en.html
        # /usr/share/doc/ppp/examples/peers-pppoe (Debian ppp package)
        files[f"/etc/ppp/peers/vs-router-{interface.name}"] = (
            f"plugin rp-pppoe.so\nnic-{interface.name}\nuser {username}\n"
            "noauth\nnoipdefault\ndefaultroute\nusepeerdns\npersist\n"
        )
        secrets.append(f"{username} * {password_word} *")
    if secrets:
        content = "\n".join(secrets) + "\n"
        files["/etc/ppp/chap-secrets"] = content
        files["/etc/ppp/pap-secrets"] = content
    return dict(sorted(files.items()))
