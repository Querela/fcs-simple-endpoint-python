"""Various useful constants for CLARIN-FCS endpoints."""
from enum import Enum

from clarin.sru.constants import SRUQueryType

# ---------------------------------------------------------------------------
# Diagnostics


FCS_DIAGNOSTIC_URI_PREFIX = "http://clarin.eu/fcs/diagnostic/"


class FCSDiagnostics(str, Enum):
    def __new__(cls, nr: int, fatal: bool, description: str):
        obj = str.__new__(cls, f"{FCS_DIAGNOSTIC_URI_PREFIX}{nr}")
        obj._value_ = f"{FCS_DIAGNOSTIC_URI_PREFIX}{nr}"
        obj.nr = nr
        obj.fatal = fatal
        obj.description = description
        obj.__doc__ = description
        return obj

    nr: int
    fatal: bool
    description: str

    # fmt: off

    PERSISTENT_IDENTIFIER_INVALID = (1, False, "Persistent identifier passed by the Client for restricting the search is invalid.")
    RESOURCE_TOO_LARGE_CONTEXT_ADJUSTED = (2, False, "Resource set too large. Query context automatically adjusted.")
    RESOURCE_TOO_LARGE_CANNOT_PERFORM_QUERY = (3, True, "Resource set too large. Cannot perform Query.")
    REQUESTED_DATA_VIEW_INVALID = (4, False, "Requested Data View not valid for this resource.")
    GENERAL_QUERY_SYNTAX_ERROR = (10, True, "General query syntax error.")
    GENERAL_QUERY_TOO_COMPLEX_CANNOT_PERFORM_QUERY = (11, True, "Query too complex. Cannot perform Query.")
    QUERY_WAS_REWRITTEN = (12, False, "Query was rewritten.")
    GENERAL_PROCESSING_HINT = (13, False, "General processing hint.")

    # fmt: on


# ---------------------------------------------------------------------------
# enums


class FCSQueryType(str, Enum):
    def __str__(self) -> str:
        return self.value

    FCS = "fcs"
    CQL = SRUQueryType.CQL
    SEARCH_TERMS = SRUQueryType.SEARCH_TERMS


class FCSLayerType(str, Enum):
    def __str__(self) -> str:
        return self.value

    TEXT = "text"
    """Textual representation of resource, also the layer that is used in Basic Search, String"""
    LEMMA = "lemma"
    """Lemmatisation, String"""
    POS = "pos"
    """Part-of-Speech annotations, Universal POS tags"""
    ORTH = "orth"
    """Orthographic transcription of (mostly) spoken resources, String"""
    NORM = "norm"
    """Orthographic normalization of (mostly) spoken resources, String"""
    PHONETIC = "phonetic"
    """Phonetic transcription, SAMPA"""


LAYER_TYPE_EXTENSION_PREFIX = "x-"


# ---------------------------------------------------------------------------
# namespaces


# from: https://docs.oracle.com/javase/7/docs/api/javax/xml/XMLConstants.html
# from xml.dom import XML_NAMESPACE
XML_NS_PREFIX = "xml"
XML_NS_URI = "http://www.w3.org/XML/1998/namespace"


FCS_NS = "http://clarin.eu/fcs/resource"
FCS_PREFIX = "fcs"
ED_NS = "http://clarin.eu/fcs/endpoint-description"
ED_PREFIX = "ed"

RI_NS_LEGACY = "http://clarin.eu/fcs/1.0/resource-info"


class FCSDataViewNamespaces(str, Enum):
    def __new__(cls, prefix: str, namespace: str, mimetype: str):
        obj = str.__new__(cls, namespace)
        obj._value_ = namespace
        obj.prefix = prefix
        obj.namespace = namespace
        obj.mimetype = mimetype
        return obj

    prefix: str
    namespace: str
    mimetype: str

    # fmt: off
    HITS = ("hits", "http://clarin.eu/fcs/dataview/hits", "application/x-clarin-fcs-hits+xml")
    KWIC = ("kwic", "http://clarin.eu/fcs/1.0/kwic", "application/x-clarin-fcs-kwic+xml")
    ADV = ("adv", "http://clarin.eu/fcs/dataview/advanced", "application/x-clarin-fcs-adv+xml")
    # fmt: on


# ---------------------------------------------------------------------------


class Capabilities(str, Enum):
    def __str__(self) -> str:
        return self.value

    BASIC_SEARCH = "http://clarin.eu/fcs/capability/basic-search"
    ADVANCED_SEARCH = "http://clarin.eu/fcs/capability/advanced-search"


# ---------------------------------------------------------------------------
# params?


LANG_EN = "en"

RESOURCE_URI_PREFIX = "resource:"

X_FCS_ENDPOINT_DESCRIPTION = "x-fcs-endpoint-description"
X_FCS_CONTEXT = "x-fcs-context"


# ---------------------------------------------------------------------------
# params


class FCSAuthenticationParam(str, Enum):
    def __str__(self) -> str:
        return self.value

    ENABLE = "eu.clarin.sru.server.fcs.authentication.enable"
    AUDIENCE = "eu.clarin.sru.server.fcs.authentication.audience"
    IGNORE_ISSUEDAT = "eu.clarin.sru.server.fcs.authentication.ignoreIssuedAt"
    ACCEPT_ISSUEDAT = "eu.clarin.sru.server.fcs.authentication.acceptIssuedAt"
    ACCEPT_EXPIRESAT = "eu.clarin.sru.server.fcs.authentication.acceptExpiresAt"
    ACCEPT_NOTBEFORE = "eu.clarin.sru.server.fcs.authentication.acceptNotBefore"

    # prefix
    PUBLIC_KEY_PREFIX = "eu.clarin.sru.server.fcs.authentication.key."


# ---------------------------------------------------------------------------
