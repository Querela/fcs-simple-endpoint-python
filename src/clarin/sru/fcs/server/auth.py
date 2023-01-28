import logging
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import jwt
from clarin.sru.constants import SRUDiagnostics
from clarin.sru.exception import SRUConfigException
from clarin.sru.exception import SRUException
from clarin.sru.server.auth import SRUAuthenticationInfo
from clarin.sru.server.auth import SRUAuthenticationInfoProvider
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm
from werkzeug import Request

# from typing import Self  # 3.11


# ---------------------------------------------------------------------------


LOGGER = logging.getLogger(__name__)


ALGORITHM_NAME = "RS256"


# ---------------------------------------------------------------------------


class AuthenticationInfo(SRUAuthenticationInfo):
    def __init__(self, subject: str):
        super().__init__()
        self._subject = subject

    @property
    def authentication_method(self) -> str:
        return "JWT"

    @property
    def subject(self) -> str:
        return self._subject


@dataclass(frozen=True)
class Key:
    key_id: str
    public_key: RSAPublicKey


@dataclass(frozen=True)
class Verifier:
    key_id: str
    public_key: RSAPublicKey
    jwt: jwt.PyJWT
    claims: Dict[str, Any]

    def decode(self, token: str, no_verification: bool = False) -> Dict[str, Any]:
        # TODO: we could probably bypass most checks by using internals like jwt.PyJWS()._load(token)
        if no_verification:
            return self.jwt.decode(token, options=dict(verify_signature=False))
        return self.jwt.decode(
            token,
            self.public_key,  # type: ignore
            algorithms=[ALGORITHM_NAME],
            **self.claims,
        )

    def verify(self, token: str) -> bool:
        # from `api_jws.py` -> `decode_complete`/`_load`/`_verify_signature`
        # TODO: not sure, better to use the stable JWT API instead of internals
        payload, signing_input, header, signature = jwt.PyJWS()._load(token)
        # algorithm = RSAAlgorithm(RSAAlgorithm.SHA256)
        # return algorithm.verify(signing_input, self.public_key, signature)
        try:
            self.jwt.decode(
                token,
                self.public_key,  # type: ignore
                algorithms=[ALGORITHM_NAME],
                **self.claims,
            )
        except (
            jwt.exceptions.InvalidAudienceError,
            jwt.exceptions.ExpiredSignatureError,
            # jwt.exceptions.InvalidIssuerError,  # NOTE: test cases required, but not 'issuers' not set, so not raised
            jwt.exceptions.InvalidIssuedAtError,  # NOTE: test cases required
        ):
            # e.g. 'Invalid audience'
            # e.g. 'Signature has expired'
            # TODO: what if verifiers with different leeways?
            raise
        except jwt.exceptions.MissingRequiredClaimError:
            # this is required, if missing, raise?
            # e.g. 'Token is missing the "aud" claim'
            raise
        except jwt.exceptions.ImmatureSignatureError:
            # TODO: fail on signature not yet 'live'?
            # e.g. 'The token is not yet valid (iat)'
            return False
        except (
            jwt.exceptions.InvalidSignatureError,  # is a DecodeError
            jwt.exceptions.DecodeError,
            jwt.exceptions.InvalidAlgorithmError,
        ):
            # here we would optimally try other keys as we could serve multiple clients
            # e.g. 'Signature verification failed'
            # e.g. 'Invalid crypto padding' / 'Invalid header string: ...' - some parts are missing
            return False
        return True


# ---------------------------------------------------------------------------


class AuthenticationProvider(SRUAuthenticationInfoProvider):
    def __init__(self, verifiers: List[Verifier]) -> None:
        super().__init__()
        self.verifiers = verifiers

    @property
    def key_count(self) -> int:
        if not self.verifiers:
            return 0
        return len(self.verifiers)

    # ----------------------------------------------------

    def get_AuthenticationInfo(
        self, request: Request
    ) -> Optional[SRUAuthenticationInfo]:
        value = request.headers.get("Authentication")
        if not value or value.isspace():
            return None

        LOGGER.debug("Found Authentication header with: '%s'", value)
        if not value.lower().startswith("bearer"):
            LOGGER.debug(
                "Authentication header with incorrect format. Expected start: 'Bearer '"
            )
            return None

        token = value[6:].strip()
        if not token:
            LOGGER.debug("No bearer token in Authentication header?")
            return None

        return self._check_token(token)

    def _check_token(self, token_raw: str) -> AuthenticationInfo:
        try:
            token = jwt.PyJWT().decode(token_raw, options=dict(verify_signature=False))
            LOGGER.debug(
                "Token: jti=%s, iss=%s, aud=%s, sub=%s, iat=%s, exp=%s, nbt=%s",
                token.get("jti"),
                token.get("iss"),
                token.get("aud"),
                token.get("sub"),
                token.get("iat"),
                token.get("exp"),
                token.get("nbt"),
            )

            # TODO: sanitize 'sub' of JWT token
            token["sub"] = str(token["sub"]) if "sub" in token else ""

            if not self.verifiers:
                LOGGER.warning("No JWT verifiers found. Return unverified 'sub' claim.")
                # NOTE: `token.get("sub")` should return a `str`
                return AuthenticationInfo(str(token.get("sub")))

            for verifier in self.verifiers:
                try:
                    LOGGER.debug(
                        "Trying to verify token with key '%s'", verifier.key_id
                    )
                    if verifier.verify(token_raw):
                        return AuthenticationInfo(str(token.get("sub")))
                # TODO: figure out exceptions we want to catch or ignore
                except jwt.exceptions.InvalidAudienceError as ex:
                    # java: InvalidClaimException
                    # e.g. audience does not match
                    raise SRUException(
                        SRUDiagnostics.AUTHENTICATION_ERROR,
                        "error processing request authentication",
                        message=str(ex),
                    ) from ex
                except jwt.exceptions.ExpiredSignatureError as ex:
                    raise SRUException(
                        SRUDiagnostics.AUTHENTICATION_ERROR,
                        "error processing request authentication",
                        message="token expired",
                    ) from ex

            raise SRUException(
                SRUDiagnostics.AUTHENTICATION_ERROR,
                "error processing request authentication",
                message="Could not verify JSON Web token signature.",
            )

        except jwt.PyJWTError as ex:
            raise SRUException(
                SRUDiagnostics.AUTHENTICATION_ERROR,
                "error processing request authentication",
                message="Could not decode JSON Web token",
            ) from ex

    # ----------------------------------------------------

    class Builder:
        def __init__(self):
            self.keys = List[Key]
            self.audiences = List[str]
            self.ignore_IssuedAt = False
            self.leeway_IssuedAt = -1
            self.leeway_ExpiresAt = -1
            self.leeway_NotBefore = -1

        @classmethod
        def create(cls) -> "AuthenticationProvider.Builder":
            return AuthenticationProvider.Builder()

        def with_audience(self, audience: str) -> "AuthenticationProvider.Builder":
            self.audiences.add(audience)
            return self

        def with_ignore_IssuedAt(self) -> "AuthenticationProvider.Builder":
            self.ignore_IssuedAt = True
            return self

        def with_IssuedAt(self, leeway: int) -> "AuthenticationProvider.Builder":
            if leeway < 0:
                raise ValueError("leeway < 0")
            self.leeway_IssuedAt = leeway
            return self

        def with_ExpiresAt(self, leeway: int) -> "AuthenticationProvider.Builder":
            if leeway < 0:
                raise ValueError("leeway < 0")
            self.leeway_ExpiresAt = leeway
            return self

        def with_NotBefore(self, leeway: int) -> "AuthenticationProvider.Builder":
            if leeway < 0:
                raise ValueError("leeway < 0")
            self.leeway_NotBefore = leeway
            return self

        def with_public_key(
            self, key_id: str, key: Any
        ) -> "AuthenticationProvider.Builder":
            self._load_public_key(key_id, key)
            return self

        def _load_public_key(self, key_id: str, key: Any) -> None:
            # RSASSA-PKCS1-v1_5 with SHA-256 ("RS256")
            # see: https://www.rfc-editor.org/rfc/rfc7519#section-8
            # https://pyjwt.readthedocs.io/en/stable/faq.html#how-can-i-extract-a-public-private-key-from-a-x509-certificate
            try:
                # algorithm_name = "RS256"
                algorithm = RSAAlgorithm(RSAAlgorithm.SHA256)
                key_obj: RSAPublicKey = algorithm.prepare_key(key)
                self.keys[key_id] = key_obj
            except (ValueError, TypeError) as ex:
                raise SRUConfigException(f"Failed to load key '{key_id}'") from ex

        def build(self) -> "AuthenticationProvider":
            verifiers: List[Verifier] = list()

            for key_id, key in self.keys.items():
                claims = dict()
                if self.audiences:
                    claims["audience"] = list(self.audiences)

                options = dict()
                if self.ignore_IssuedAt:
                    options["verify_iat"] = False
                else:
                    pass
                if self.leeway_ExpiresAt > 0:
                    options["leeway"] = self.leeway_ExpiresAt

                # both IssuedAd (IAT) and NotBefore (NBF) should be the
                # same based on fcs-simple-client (auth)
                # unfortunately PyJWT does not have separate leeways
                # see: com.auth0.jwt.interfaces.Verification
                # TODO: warn? or just use min/max/avg from all?
                # if self.leeway_IssuedAt > 0:
                #     options["leeway"] = self.leeway_IssuedAt
                # if self.leeway_NotBefore > 0:
                #     options["leeway"] = self.leeway_NotBefore

                verifiers.append(
                    Verifier(
                        key_id=key_id,
                        public_key=key,
                        jwt=jwt.PyJWT(**options),
                        claims=claims,
                    )
                )

            return AuthenticationProvider(verifiers)


# ---------------------------------------------------------------------------
