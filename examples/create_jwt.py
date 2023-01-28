"""

from: https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9
create key:

    ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
    #openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub

from: https://blog.digital-craftsman.de/generate-a-new-jwt-public-and-private-key/
create key:

    openssl genrsa -out private.pem 4096
    openssl rsa -pubout -in private.pem -out public.pem

CLARIN:
    - https://cloud.fripost.org/s/K49go8pARLEA5tY?dir=undefined&openfile=1946589
    - https://github.com/clarin-eric/fcs-simple-client/blob/main/src/main/java/eu/clarin/sru/client/auth/ClarinFCSRequestAuthenticator.java

Docs:
    - https://jwt.io/
        - https://jwt.io/libraries
            - https://github.com/lepture/authlib  -- 2022-12-27
            - https://github.com/latchset/jwcrypto/  -- 2022-10-10
            - https://github.com/mpdavis/python-jose/  -- 2022-02-09
                - claims: https://python-jose.readthedocs.io/en/latest/jwt/index.html
            - https://github.com/jpadilla/pyjwt/  -- 2022-02-01
    - https://www.rfc-editor.org/rfc/rfc7519#section-8

"""

# import calendar
import datetime
import json
import logging
import os.path
import random
import time

import jwt

# from jwt.algorithms import RSAAlgorithm

LOGGER = logging.getLogger(__name__)
HERE = os.path.dirname(__file__)

KEY_PRIV = "jwtRS256.key"
KEY_PUB = f"{KEY_PRIV}.pub"

# KEY_PRIV = "private.pem"
# KEY_PUB = "public.pem"

KEY_PRIV = os.path.join(HERE, KEY_PRIV)
KEY_PUB = os.path.join(HERE, KEY_PUB)

ALGORITHM = "RS256"

EXPIRE_TIME = 2
AUDIENCE1 = "endpoint-uri"
AUDIENCE = [AUDIENCE1, "endpoint-uri-2"]


def generate_token():
    LOGGER.info("Create token")

    # now = calendar.timegm(datetime.datetime.now(tz=datetime.timezone.utc).utctimetuple())
    now = int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())
    # now += 10  # future
    # now -= 10  # past
    LOGGER.info("time: %s", now)
    LOGGER.info("expiretime: %s (+%s)", now + EXPIRE_TIME, EXPIRE_TIME)
    next_token_id = str(int(random.random() * 2**30))  # or use UUID
    LOGGER.info("token-id: %s", next_token_id)

    # the aggregator creates the token
    # agg: iss/exp optional
    # agg: aud required
    # agg: sub?
    payload = {
        # issuer
        "iss": "me the aggregator?",
        # audience (all the endpoints)
        "aud": AUDIENCE,
        # subject -- authInfoProvider.getSubject(endpointURI)
        "sub": AUDIENCE1,  # or other content: 1
        # JWT ID
        "jti": next_token_id,
        # timestamps: issuedAt, notBefore, expiresAt
        "iat": now,
        "nbf": now,
        "exp": now + EXPIRE_TIME,
        # content
        "userID": "email,eduPersonPrincipalName,eduPersonTargetedID",
    }
    LOGGER.info("payload: %s", json.dumps(payload))

    with open(KEY_PRIV, "rb") as fp:
        key = fp.read()

    token = jwt.encode(payload, key, ALGORITHM)
    LOGGER.info("token: %s", token)
    return token


def check_token(token):
    LOGGER.info("Check token")
    LOGGER.info("token: %s", token)

    now = int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())
    LOGGER.info("time: %s", now)

    with open(KEY_PUB, "rb") as fp:
        key = fp.read()

    headers = jwt.get_unverified_header(token)
    LOGGER.info("headers: %s", json.dumps(headers))

    data = jwt.decode(
        token,
        key,
        algorithms=[ALGORITHM],
        audience=AUDIENCE1,
        options=dict(verify_signature=True),
        leeway=5,
        # options={"require": ["exp", "iss", "sub"]},
    )
    # jwt.exceptions.InvalidAudienceError: Invalid audience
    # jwt.exceptions.ImmatureSignatureError: The token is not yet valid (iat)
    # jwt.exceptions.ExpiredSignatureError: Signature has expired
    # jwt.exceptions.MissingRequiredClaimError: Token is missing the "aud" claim
    # jwt.exceptions.InvalidSignatureError: Signature verification failed
    # jwt.exceptions.DecodeError: Invalid crypto padding
    # jwt.exceptions.DecodeError: Invalid header string: ...
    LOGGER.info("payload: %s", json.dumps(data))


def verify_token(token):
    LOGGER.info("Verify token")
    LOGGER.info("token: %s", token)

    payload, signing_input, header, signature = jwt.PyJWS()._load(token)

    with open(KEY_PUB, "rb") as fp:
        key = fp.read()

    # algorithm = RSAAlgorithm(RSAAlgorithm.SHA256)
    algorithm = jwt.get_algorithm_by_name(ALGORITHM)
    key = algorithm.prepare_key(key)
    ok = algorithm.verify(signing_input, key, signature)
    LOGGER.info("ok? %s", ok)

    return ok


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    TOKEN = generate_token()

    LOGGER.info("raw-decode: %s", json.loads(jwt.PyJWS()._load(TOKEN)[0]))
    LOGGER.info(
        "decode-no-key: %s", jwt.decode(TOKEN, options=dict(verify_signature=False))
    )

    if verify_token(TOKEN):
        time.sleep(3)
        check_token(TOKEN)
