# IVT Vent 402 Local LAN API

Direct local access to the legacy HTTP API on an **IVT Vent 402**, without Bosch cloud or XMPP.

> **Tested on:** IVT Vent 402, gateway firmware `04.08.02`
>
> Other IVT/Bosch gateways using the same legacy IVT protocol may also work, but have not been verified.

## Overview

The IVT Vent 402 exposes an encrypted HTTP API directly on the local network.

Communication is:

```text
Application
    │
    │ HTTP GET
    ▼
IVT gateway :80
    │
    │ Base64(AES-256-ECB(JSON))
    ▼
Local decryption

No Bosch cloud connection, XMPP connection, HTTP authentication, cookies or bearer tokens are required for local reads.

The tested request format is:

GET /system/brand HTTP/1.1
Host: <gateway-ip>
User-Agent: TeleHeater
Connection: keep-alive
Content-Type: application/json



The response body is Base64-encoded AES-256-ECB ciphertext containing the JSON resource.

Requirements

You need:

the IVT gateway's local IP address;
the legacy IVT LAN access token;
a personal LAN password;
access to the same LAN as the heat pump.
Enable LAN-only access

Use the original/legacy IVT Anywhere application and configure the heat pump as a LAN-only connection.

During setup, the app asks you to create a personal/device password.

Save this password. It is used as the second component of the local API encryption key.

Credentials

Two values are required.

IVT_LAN_ACCESS_TOKEN

The legacy LAN access token associated with the gateway.

Hyphens are removed before key derivation.

IVT_LAN_ACCESS_TOKEN=<legacy LAN access token>
IVT_PERSONAL_PASSWORD

The personal password created during the legacy IVT Anywhere LAN-only setup.

IVT_PERSONAL_PASSWORD=<LAN personal password>

Preserve this value exactly as entered.

Do not remove characters, change case, hash it, Base64-encode it or otherwise transform it.

HTTP API

The gateway listens on:

http://<gateway-ip>:80

For example:

http://192.168.1.50

Requests use:

User-Agent: TeleHeater
Connection: keep-alive
Content-Type: application/json

A read is a normal body-less HTTP GET:

GET /system/brand HTTP/1.1
Host: 192.168.1.50
User-Agent: TeleHeater
Connection: keep-alive
Content-Type: application/json



There is no:

Authorization header
HTTP Basic authentication
Bearer token
Cookie
encrypted request body

The credentials are used to decrypt the response, not sent with the GET.

Key derivation

The protocol uses this fixed IVT magic value:

867845e97c4e29dce522b9a7d3a3e07b
152bffadddbed7f5ffd842e9895ad1e4

This represents 32 binary bytes, not a 64-character ASCII string.

Python:

magic = bytes.fromhex(
    "867845e97c4e29dce522b9a7d3a3e07b"
    "152bffadddbed7f5ffd842e9895ad1e4"
)

Normalize the LAN access token:

access = IVT_LAN_ACCESS_TOKEN.replace("-", "")

Then derive two MD5 binary digests:

part1 = MD5(
    UTF8(access) || magic
)


part2 = MD5(
    magic || UTF8(personal_password)
)


AES_key = part1.binary_digest || part2.binary_digest

Each MD5 digest is 16 bytes:

16 bytes + 16 bytes = 32 bytes

giving an AES-256 key.

Python:

import hashlib


access_bytes = access.encode("utf-8")
password_bytes = IVT_PERSONAL_PASSWORD.encode("utf-8")


part1 = hashlib.md5(access_bytes + magic).digest()
part2 = hashlib.md5(magic + password_bytes).digest()


key = part1 + part2


assert len(key) == 32

Use the binary MD5 digest bytes, not the hexadecimal MD5 strings.

Response format

A successful protected request returns:

HTTP 200
Content-Type: application/json

The body contains Base64-encoded ciphertext.

Some responses begin with CR/LF whitespace:

\r\n<Base64 ciphertext>

Processing is:

HTTP body
    ↓
strip surrounding ASCII whitespace
    ↓
standard Base64 decode
    ↓
AES-256-ECB decrypt
    ↓
remove trailing NUL bytes
    ↓
UTF-8 decode
    ↓
JSON parse

AES parameters:

Cipher:  AES-256
Mode:    ECB
IV:      none
Padding: none

The decoded ciphertext must be a multiple of the AES block size:

16 bytes
Reading the complete HTTP response

The gateway may omit Content-Length.

If Content-Length is absent, continue reading until the server closes the connection.

Do not attempt to decrypt only the first TCP chunk received.

A partial response can produce:

invalid Base64
non-block-aligned ciphertext
decryption errors

even when the API response itself is valid.

Python decryption example

The following demonstrates the protocol.

It requires an AES implementation such as PyCryptodome:

pip install pycryptodome
import base64
import hashlib
import json
import os


from Crypto.Cipher import AES


magic = bytes.fromhex(
    "867845e97c4e29dce522b9a7d3a3e07b"
    "152bffadddbed7f5ffd842e9895ad1e4"
)


access_token = os.environ["IVT_LAN_ACCESS_TOKEN"]
personal_password = os.environ["IVT_PERSONAL_PASSWORD"]


access = access_token.replace("-", "").encode("utf-8")
password = personal_password.encode("utf-8")


key = (
    hashlib.md5(access + magic).digest()
    + hashlib.md5(magic + password).digest()
)


def decrypt_ivt_response(body: bytes):
    # Gateway responses can contain leading CR/LF.
    encoded = body.strip()


    ciphertext = base64.b64decode(
        encoded,
        validate=True
    )


    if len(ciphertext) % AES.block_size != 0:
        raise ValueError(
            "Ciphertext is not AES block aligned; "
            "the HTTP response may be incomplete"
        )


    cipher = AES.new(key, AES.MODE_ECB)


    plaintext = cipher.decrypt(ciphertext)


    # Legacy IVT responses use trailing NUL padding.
    plaintext = plaintext.rstrip(b"\x00")


    text = plaintext.decode("utf-8")


    return json.loads(text)
Example local request

Using Python's HTTP client:

import urllib.request


gateway = "192.168.1.50"
path = "/system/brand"


headers = {
    "User-Agent": "TeleHeater",
    "Connection": "keep-alive",
    "Content-Type": "application/json",
}


request = urllib.request.Request(
    f"http://{gateway}{path}",
    headers=headers,
)


with urllib.request.urlopen(request, timeout=10) as response:
    body = response.read()


resource = decrypt_ivt_response(body)


print(resource)

A successful /system/brand response contains:

IVT
Validated resources

The following resources were successfully read directly over the LAN on an IVT Vent 402 running firmware 04.08.02.

Brand
/system/brand

Example value:

IVT
Gateway firmware
/gateway/versionFirmware

Example:

04.08.02
System information
/system/info

Returns a system-information JSON object.

Heat-source supply temperature
/heatSources/actualSupplyTemperature

Example value:

24.1 °C

The gateway also exposes resource trees including:

/gateway
/system
/heatSources
/heatingCircuits
/dhwCircuits
/recordings
/notifications
/solarCircuits

Available resources depend on the installed heat-pump configuration.

Resource metadata

Resources are returned as JSON objects containing metadata and values.

Typical fields include:

{
  "id": "/heatSources/actualSupplyTemperature",
  "writeable": 0,
  "value": 24.1
}

For monitoring applications, resources marked:

writeable: 0

are read-only.

Troubleshooting
HTTP 403
HTTP/1.0 403 Forbidden

means the gateway has not granted access to the protected local API.

Configure the gateway using the original IVT Anywhere application's LAN-only connection setup and create a personal LAN password.

A 403 occurs before response encryption, so changing AES parameters will not resolve it.

HTTP 200 but decryption fails

If the response:

returns HTTP 200
contains valid Base64
decodes to AES-block-aligned ciphertext

but does not decrypt to valid JSON, verify the credential roles.

The required combination is:

legacy IVT LAN access token
+
personal password created for LAN-only access

Do not substitute Bosch cloud credentials or similarly named gateway/connection passwords.

Ciphertext is not divisible by 16

The complete response probably has not been read.

Read:

Content-Length bytes

when the header exists.

Otherwise continue receiving data until the server closes the connection.

Tested configuration
Heat pump:        IVT Vent 402
Gateway firmware: 04.08.02
Transport:        Local HTTP / TCP 80
Client identity:  TeleHeater
Response format:  Base64
Encryption:       AES-256-ECB
Key derivation:   MD5 + MD5
Cloud required:   No
XMPP required:    No

Disclaimer

This project is an independent interoperability project and is not affiliated with, endorsed by, or supported by IVT or Bosch.

The procedure has been verified on an IVT Vent 402 running gateway firmware 04.08.02. Other controllers, firmware versions and gateway generations may behave differently.
