import argparse
import base64
import hmac
import os
import time
import urllib.parse

import tqdm

import topgen.payload_pb2 as payload_pb2

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
    for i, p in enumerate(payload.otp_parameters):
        print(f"#{i}")
        print_item(p)


def print_item(p):
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


def get_name(p):
    return f"{p.issuer} ({p.name})"


def main(args):
    try:
        payload = payload_pb2.Payload()
        if os.path.exists(args.db):
            read(args.db, payload)
        if args.url:
            payload.MergeFrom(decode_url(args.url))
            save(args.db, payload)

        if args.add:
            secret = input("Secret > ")
            try:
                secret = base64.b32decode(secret.replace(" ", ""))
            except Exception:
                print(f'Given secret "{secret}" is not valid. Secret must be base32 decodeable.')
                return
            name = input("Name > ")
            issuer = input("Issuer > ")
            p = payload.otp_parameters.add()
            p.secret = secret
            p.name = name
            p.issuer = issuer
            p.algorithm = payload_pb2.Payload.Algorithm.ALGORITHM_SHA1
            p.digits = payload_pb2.Payload.DigitCount.DIGIT_COUNT_SIX
            p.type = payload_pb2.Payload.OtpType.OTP_TYPE_TOTP
            save(args.db, payload)

        payload.otp_parameters.sort(key=lambda p: get_name(p))
        num_items = len(payload.otp_parameters)
        if num_items > 0:
            if args.remove:
                list_items(payload)
                index = int(input(f"Select index to delete [0-{num_items - 1}]> "))
                if index < 0 or index >= num_items:
                    print(f"Index have to be between 0-{len(num_items - 1)}")
                    return
                print_item(payload.otp_parameters[index])
                answer = input("Are you sure to delete above item? [y,N] > ")
                if answer == "y":
                    del payload.otp_parameters[index]
                    save(args.db, payload)
                    print("Item has been deleted")
                else:
                    print("Item has not been deleted")
                return

            if args.list:
                list_items(payload)
                return

            while True:
                counter = int(time.time() // INTERVAL)
                print()
                for p in payload.otp_parameters:
                    print(f"{get_name(p)}: {totp(p.secret, counter)}")
                print()
                with tqdm.tqdm(total=INTERVAL, bar_format="{bar}") as progress:
                    prev_time = 0
                    while int(time.time() % INTERVAL) > 0:
                        curr_time = time.time() % INTERVAL
                        progress.update(curr_time - prev_time)
                        prev_time = curr_time
                        time.sleep(0.5)
                time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser("TOPGen - Time-based one-time password generator")
    parser.add_argument("--db", required=False, default="payload.db", help="file path to store keys")
    parser.add_argument(
        "--url",
        required=False,
        help='URL in the form of "otpauth-migration://offline?data=..." to import keys from',
    )
    parser.add_argument("--list", action="store_true", help="list all the keys with their details")
    parser.add_argument("--add", action="store_true", help="add a new key")
    parser.add_argument("--remove", action="store_true", help="remove a key")
    args = parser.parse_args()
    main(args)
