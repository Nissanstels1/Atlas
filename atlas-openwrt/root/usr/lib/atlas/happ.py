"""Local Happ crypt5 and authenticated subscription-body interoperability.

No network, executable loading, certificate bypass or device-ID modification.
Protocol constants are separate from the implementation; see docs/happ.md.
"""
import base64
import binascii
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

KEY_FILE = Path(__file__).with_name('happ-keys.json')
MAX_LINK = 16384
MAX_BODY = 2 * 1024 * 1024

class HappError(ValueError):
    pass

def _keys():
    try:
        return json.loads(KEY_FILE.read_text())
    except (OSError, ValueError) as exc:
        raise HappError('Не найдены данные совместимости Happ. Переустановите пакет Atlas.') from exc

def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        return serialization, padding, AESGCM, ChaCha20Poly1305
    except ImportError as exc:
        raise HappError('Для Happ установите пакет python3-cryptography.') from exc

def _b64(data):
    if isinstance(data, str):
        data = data.encode('ascii')
    data = re.sub(rb'\s+', b'', data).rstrip(b'=')
    return base64.b64decode(data + b'=' * (-len(data) % 4), altchars=b'-_', validate=True)

def _permute(data, order):
    width = len(order)
    end = len(data) // width * width
    return bytes(data[i+j] for i in range(0, end, width) for j in order) + data[end:]

def decrypt_link(link):
    if not isinstance(link, str) or len(link) > MAX_LINK or not link.startswith('happ://crypt5/'):
        raise HappError('Поддерживается ссылка happ://crypt5/ длиной до 16 КиБ.')
    try:
        raw = link[len('happ://crypt5/'):].encode('ascii')
        if any(x <= 32 or x >= 127 for x in raw) or len(raw) < 24:
            raise ValueError()
        packet = _permute(raw, (2, 3, 0, 1))
        marker = (packet[:4] + packet[-4:]).decode('ascii')
        encoded_key = _keys()['crypt5'].get(marker)
        if not encoded_key:
            raise HappError('Неизвестная версия ключа Happ. Нужны обновлённые данные совместимости.')
        serialization, padding, _, chacha = _crypto()
        private_key = serialization.load_der_private_key(_b64(encoded_key), password=None)
        body = packet[4:-4]
        # Each layout must pass authenticated decryption; parsing alone is insufficient.
        for salted in (True, False):
            try:
                start = 22 if salted else 12
                m = re.match(rb'[0-9]{1,6}', body[start:])
                if not m:
                    continue
                count = int(m[0]);offset = start + len(m[0]) + 1
                if not 1 <= count <= len(body) - offset:
                    continue
                cipher = _b64(body[offset:offset+count])
                wrapped = _b64(body[offset+count:])
                material = private_key.decrypt(wrapped, padding.PKCS1v15())
                secret = _b64(_permute(material, (1, 0)))
                if len(secret) != 32:
                    continue
                if salted:
                    salt = body[14:22]
                    secret = bytes(x ^ salt[i % 8] for i, x in enumerate(secret))
                decoded = chacha(secret).decrypt(body[:12], cipher, None)
                result = _b64(_permute(decoded, (1, 0))).decode('utf-8')
                if len(result) > 4096:
                    raise ValueError()
                return result
            except Exception:
                continue
    except HappError:
        raise
    except Exception as exc:
        raise HappError('Некорректная ссылка Happ; содержимое не импортировано.') from exc
    raise HappError('Не удалось проверить и расшифровать ссылку Happ.')

def decrypt_body(url, body, tag):
    # A query parameter alone is not proof of encryption. Plain subscriptions pass unchanged.
    if tag is None:
        return body
    if not isinstance(body, bytes) or len(body) > MAX_BODY or not isinstance(tag, str) or len(tag) > 128:
        raise HappError('Некорректный зашифрованный ответ Happ.')
    ids = parse_qs(urlsplit(url).query).get('key', [])
    if len(ids) != 1:
        raise HappError('В зашифрованной подписке нет однозначного идентификатора ключа.')
    encoded = _keys()['aes'].get(ids[0])
    if not encoded:
        raise HappError('Ключ шифрования содержимого Happ не поддерживается этой версией Atlas.')
    _, _, aes, _ = _crypto()
    try:
        auth = _b64(tag)
        secret = _b64(encoded)
        if len(auth) != 16 or len(secret) != 16:
            raise ValueError()
        return aes(secret).decrypt(b'kkkkkkkkkkkk', _b64(body) + auth, None)
    except Exception as exc:
        raise HappError('Проверка подлинности зашифрованной подписки не прошла; прежние профили сохранены.') from exc
