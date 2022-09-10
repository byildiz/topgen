import os
import base64
import urllib.parse
import payload_pb2
import hmac
import time
import argparse
import tqdm

INTERVAL = 30

# https://stackoverflow.com/questions/8529265/google-authenticator-implementation-in-python
# https://stackoverflow.com/a/69343235/7075029
# TOTP: Time-Based One-Time Password Algorithm: https://www.rfc-editor.org/rfc/rfc6238
# HOTP: An HMAC-Based One-Time Password Algorithm: https://www.rfc-editor.org/rfc/rfc4226
def totp(key: bytes, counter: int):
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, "sha1").digest()
    offset = digest[19] & 0xF
    code = digest[offset : offset + 4]
    code = int.from_bytes(code, "big") & 0x7FFFFFFF
    code = code % 1000000
    return "{:06d}".format(code)


def list_items(payload):
    for p in payload.otp_parameters:
        print("Secret:", base64.b32encode(p.secret).decode())
        print("Name: ", p.name)
        print("Issuer: ", p.issuer)
        print("Algorithm: ", p.algorithm)
        print("Digits: ", p.digits)
        print("Type: ", p.type)
        print("Counter: ", p.counter)
        print()


def decode_url(url):
    url = urllib.parse.urlparse(url)
    data = urllib.parse.parse_qs(url.query)["data"][0]
    bin = base64.b64decode(data)
    payload = payload_pb2.Payload()
    payload.ParseFromString(bin)
    return payload


def save(filename, payload):
    with open(filename, "wb") as f:
        f.write(payload.SerializeToString())


def read(filename, payload):
    with open(filename, "rb") as f:
        payload.ParseFromString(f.read())


if __name__ == "__main__":
    parser = argparse.ArgumentParser("TOPG - Time-based one-time password generator")
    parser.add_argument("--db", required=False, default="payload.db")
    parser.add_argument("--url", required=False)
    args = parser.parse_args()

    try:
        payload = payload_pb2.Payload()
        if os.path.exists(args.db):
            read(args.db, payload)
        if args.url:
            payload.MergeFrom(decode_url(args.url))
        save(args.db, payload)

        if len(payload.otp_parameters) > 0:
            while True:
                counter = int(time.time() // INTERVAL)
                for p in payload.otp_parameters:
                    print(f"{p.issuer} ({p.name}): {totp(p.secret, counter)}")
                print()
                with tqdm.tqdm(total=INTERVAL, bar_format="{bar}") as progress:
                    prev_time = 0
                    while int(time.time() % INTERVAL) > 0:
                        curr_time = time.time() % INTERVAL
                        progress.update(curr_time - prev_time)
                        prev_time = curr_time
                        time.sleep(0.5)
                print()
                time.sleep(1)
    except KeyboardInterrupt:
        pass
