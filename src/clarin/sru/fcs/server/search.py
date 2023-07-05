import importlib.resources
import logging
import warnings
from abc import ABCMeta
from abc import abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict
from typing import List
from typing import Optional
from xml.sax import ContentHandler
from xml.sax import SAXException

import cql
import cql.parser
from clarin.sru.constants import SRUDiagnostics
from clarin.sru.diagnostic import SRUDiagnosticList
from clarin.sru.exception import SRUConfigException
from clarin.sru.exception import SRUException
from clarin.sru.queryparser import SRUQueryParserRegistry
from clarin.sru.server.auth import SRUAuthenticationInfoProvider
from clarin.sru.server.auth import SRUAuthenticationInfoProviderFactory
from clarin.sru.server.config import SRUServerConfig
from clarin.sru.server.request import SRURequest
from clarin.sru.server.result import SRUExplainResult
from clarin.sru.server.result import SRUScanResultSet
from clarin.sru.server.server import SRUSearchEngine
from clarin.sru.xml.writer import SRUXMLStreamWriter
from clarin.sru.xml.writer import XMLStreamWriterHelper

from clarin.sru.fcs.constants import ED_NS
from clarin.sru.fcs.constants import ED_PREFIX
from clarin.sru.fcs.constants import RESOURCE_URI_PREFIX
from clarin.sru.fcs.constants import X_FCS_ENDPOINT_DESCRIPTION
from clarin.sru.fcs.constants import XML_NS_PREFIX
from clarin.sru.fcs.constants import XML_NS_URI
from clarin.sru.fcs.constants import FCSAuthenticationParam
from clarin.sru.fcs.queryparser import FCSQueryParser
from clarin.sru.fcs.server.auth import AuthenticationProvider

# ---------------------------------------------------------------------------


LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Layer:
    """This class is used to information about a Layers that is
    available by the endpoint."""

    class ContentEncoding(str, Enum):
        """The content encoding policy for a Layer."""

        def __str__(self) -> str:
            return self.value

        VALUE = "value"
        """Value information is encoded as element content in this
        layer."""
        EMPTY = "empty"
        """No additional value information is encoded for this layer."""

    # ----------------------------------------------------

    id: str
    """The identifier of the layer"""
    result_id: str
    """The unique URI that used in the Advanced Data View to refer
    to this layer"""
    type: str
    """The type identifier for the layer"""
    encoding: ContentEncoding
    """The content encoding for this layer"""
    qualifier: Optional[str] = None
    """An optional layer qualifier to be used in FCS-QL to refer to
    this layer or ``None``. Defaults to ``None``."""
    alt_ValueInfo: Optional[str] = None
    """An additional information about the layer or ``None``.
    Defaults to ``None``."""
    alt_ValueInfo_url: Optional[str] = None
    """An additional URI for pointing to more information about the
    layer or ``None``. Defaults to ``None``."""

    def __post_init__(self):
        if self.id is None:
            raise TypeError("id is None")
        if self.result_id is None:
            raise TypeError("result_id is None")
        if self.type is None:
            raise TypeError("type is None")
        if self.encoding is None:
            raise TypeError("encoding is None")

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}"
            f"[id={self.id}, result-id={self.result_id}, type={self.type}"
            f"{', qualifier=' + self.qualifier if self.qualifier else ''}]"
        )


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataView:
    """This class is used to hold information about a data view that
    is implemented by the endpoint."""

    class DeliveryPolicy(str, Enum):
        """Enumeration to indicate the delivery policy of a data view."""

        def __str__(self) -> str:
            return self.value

        SEND_BY_DEFAULT = "send-by-default"
        """The data view is sent automatically  by the endpoint."""
        NEED_TO_REQUEST = "need-to-request"
        """A client must explicitly request the endpoint."""

    # ----------------------------------------------------

    identifier: str
    """A unique short identifier for the data view"""
    mimetype: str
    """The MIME type of the data view"""
    deliveryPolicy: DeliveryPolicy
    """The delivery policy for this data view"""

    def __post_init__(self):
        if self.identifier is None:
            raise TypeError("identifier is None")
        elif self.identifier.isspace():
            raise ValueError("identifier is empty")
        if self.mimetype is None:
            raise TypeError("mimetype is None")
        elif self.mimetype.isspace():
            raise ValueError("mimetype is empty")
        if self.deliveryPolicy is None:
            raise TypeError("identifier is None")

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}"
            f"[identifier={self.identifier}, mimeType={self.mimetype}]"
        )


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceInfo:
    """This class implements a resource info record, which provides
    supplementary information about a resource that is available at
    the endpoint."""

    pid: str
    """Rhe persistent identifier of the resource"""
    title: Dict[str, str]
    """The title of the resource represented as a map with pairs of
    language code and title"""
    description: Optional[Dict[str, str]]
    """The description of the resource represented as a map with pairs
    of language code and description or ``None`` if not applicable"""
    landing_page_uri: Optional[str]
    """A URI to the landing page of the resource or ``None`` if not
    applicable"""
    languages: List[str]
    """The languages represented within this resource represented as
    a list of ISO-632-3 three letter language codes"""
    available_DataViews: List[DataView]
    """The list of available data views for this resource"""
    available_Layers: Optional[List[Layer]] = None
    """The list if layers available for Advanced Search or ``None``
    if not applicable"""
    sub_Resources: Optional[List["ResourceInfo"]] = None
    """A list of resource sub-ordinate to this resource or ``None``
    if not applicable"""

    def __post_init__(self):
        if self.pid is None:
            raise TypeError("pid is None")
        if self.title is None:
            raise TypeError("title is None")
        elif not self.title:
            raise ValueError("title is empty")
        if self.languages is None:
            raise TypeError("languages is None")
        elif not self.languages:
            raise ValueError("languages is empty")
        if self.available_DataViews is None:
            raise TypeError("available_DataViews is None")

        # clear out
        if not self.description:
            object.__setattr__(self, "description", None)
        if not self.available_Layers:
            object.__setattr__(self, "available_Layers", None)
        if not self.sub_Resources:
            object.__setattr__(self, "sub_Resources", None)

    # ----------------------------------------------------

    def get_title(self, language: str) -> Optional[str]:
        """Get the title of the resource for a specific language code.

        Args:
            language: the language code (ISO-632-3 three letter
                language code)

        Returns:
            Optional[str]: the title for the language code or ``None`` if not title for this language code exists
        """
        return self.title.get(language)

    def get_description(self, language: str) -> Optional[str]:
        """Get the description of the resource for a specific language
        code.

        Args:
            language: the language code (ISO-632-3 three letter
                language code)

        Returns:
            Optional[str]: the description for the language code or ``None`` if not description for this language code exists.
        """
        if not self.description:
            return None
        return self.description.get(language)

    # ----------------------------------------------------

    def has_available_Layers(self) -> bool:
        """Check if any layers are available for Advanced Search.

        Returns:
            bool: ``True`` if any layer for Advanced Search is available, ``False`` otherwise
        """
        return bool(self.available_Layers)

    def has_sub_Resources(self) -> bool:
        """Determine, if this resource has sub-resources.

        Returns:
            bool: ``True`` if the resource has sub-resources, ``False`` otherwise
        """
        return bool(self.sub_Resources)


# ---------------------------------------------------------------------------


class EndpointDescription(metaclass=ABCMeta):
    """An interface for abstracting resource endpoint descriptions.
    This interface allows you to provide a version of a endpoint
    description tailored to your environment.

    The implementation of this interface **must** be thread-safe.
    """

    VERSION_1 = 1
    """Constant for endpoint description version number for FCS 1.0"""
    VERSION_2 = 2
    """Constant for endpoint description version number for FCS 2.0"""

    PID_ROOT = "root"
    """Constant for a (synthetic) persistent identifier identifying
    the top-most (= root) resources in the resource inventory."""

    @abstractmethod
    def destroy(self) -> None:
        """Destroy the resource info inventory. Use this method for
        any cleanup the resource info inventory needs to perform upon
        termination, i.e. closing of persistent database connections,
        etc."""

    @abstractmethod
    def get_version(self) -> int:
        """Get the version number of this endpoint description.
        Valid version are 1 for FCS 1.0 and 2 for FCS 2.0.

        Returns:
            int: the version number for this endpoint description
        """

    @abstractmethod
    def is_version(self, version: int) -> bool:
        """Check if this endpoint description is in a certain version.

        Args:
            version: the version to check for

        Returns:
            bool: ``True`` if version number matches
        """

    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """Get the list of capabilities supported by this endpoint.
        The list contains the appropriate URIs defined by the
        CLARIN-FCS specification to indicate support for certain
        capabilities. This list **must** always contain at least
        ``http://clarin.eu/fcs/capability/basic-search`` for the
        **Basic Search** capability.

        The implementation of this method **must** be thread-safe.

        Returns:
            List[str]: the list of capabilities supported by this endpoint
        """

    @abstractmethod
    def get_supported_DataViews(self) -> List[DataView]:
        """Get the list of data views supported by this endpoint.
        This list **must** always contain an entry for the
        **Generic Hits (HITS)** data view.

        The implementation of this method **must** be thread-safe.

        Returns:
            List[DataView]: the list of data views supported by this endpoint
        """

    @abstractmethod
    def get_supported_Layers(self) -> List[Layer]:
        """Get the list of layers that are supported in Advanced
        Search by this endpoint.

        The implementation of this method **must** be thread-safe.

        Returns:
            List[Layer]: the list of layers supported in Advanced Search by this endpoint
        """

    @abstractmethod
    def get_ResourceInfos(self, pid: str) -> Optional[List[ResourceInfo]]:
        """Get a list of all resources sub-ordinate to a resource
        identified by a given persistent identifier.

        The implementation of this method **must** be thread-safe.

        Args:
            pid: the persistent identifier of the superior resource

        Returns:
            List[ResourceInfo]: a list of all sub-ordinate ResourceInfo or ``None`` if not applicable

        Raises:
            `SRUException`: if an error occurred
        """


class EndpointDescriptionBase(EndpointDescription, metaclass=ABCMeta):
    """An abstract base class for implementing endpoint descriptions.
    It already implements the methods required for capabilities and
    supported data views."""

    def __init__(
        self,
        version: int,
        capabilities: List[str],
        supported_DataViews: List[DataView],
        supported_Layers: Optional[List[Layer]],
    ) -> None:
        """[Constructor]

        Args:
            version: version of this endpoint description
            capabilities: a list of capabilities supported by this endpoint
            supported_DataViews: a list of data views that are supported by this endpoint
            supported_Layers: a list of layers that are supported by this endpoint

        Raises:
            TypeError: if arguments are invalid (None)
            ValueError: if argument values are not allowed
        """
        super().__init__()
        if version not in (1, 2):
            raise ValueError("version must be either 1 or 2")
        if capabilities is None:
            raise TypeError("capabilities is None")
        if not capabilities:
            raise ValueError("capabilities is empty")
        for capability in capabilities:
            if not capability:
                raise ValueError("capabilities must not contain a 'None'/empty item")
        if supported_DataViews is None:
            raise TypeError("supported_DataViews is None")
        if not supported_DataViews:
            raise ValueError("supported_DataViews is empty")
        for supported_DataView in supported_DataViews:
            if not supported_DataView:
                raise ValueError(
                    "supported_DataViews must not contain a 'None'/empty item"
                )
        if not supported_Layers:
            supported_Layers = list()
        for supported_Layer in supported_Layers:
            if not supported_Layer:
                raise ValueError(
                    "supported_Layers must not contain a 'None'/empty item"
                )

        self.version = version
        self.capabilities = list(capabilities)
        self.supported_DataViews = list(supported_DataViews)
        self.supported_Layers = list(supported_Layers)

    def get_version(self) -> int:
        return self.version

    def is_version(self, version: int) -> bool:
        return self.version == version

    def get_capabilities(self) -> List[str]:
        return self.capabilities

    def get_supported_DataViews(self) -> List[DataView]:
        return self.supported_DataViews

    def get_supported_Layers(self) -> List[Layer]:
        return self.supported_Layers


class SimpleEndpointDescription(EndpointDescriptionBase):
    """A very simple implementation of an endpoint description that
    is initialized from static information supplied at construction
    time. Mostly used together with `SimpleEndpointDescriptionParser`,
    but it is agnostic how the static list of resource info records
    is generated."""

    def __init__(
        self,
        version: int,
        capabilities: List[str],
        supported_DataViews: List[DataView],
        supported_Layers: List[Layer],
        resources: List[ResourceInfo],
        pid_case_sensitive: bool,
    ) -> None:
        """Constructor.

        Args:
            version: version of this endpoint description
            capabilities: a list of capabilities supported by this endpoint
            supported_DataViews: a list of data views that are supported by this endpoint
            supported_Layers: a list of layers supported for Advanced Search by this endpoint or ``None``
            resources: a static list of resource info records
            pid_case_sensitive: ``True`` if comparison of persistent identifiers should be performed case-sensitive, ``False`` otherwise

        Raises:
            TypeError: if resources are None
        """
        super().__init__(version, capabilities, supported_DataViews, supported_Layers)
        if resources is None:
            raise TypeError("entries/resources is None")

        self.entries = list(resources)
        self.pid_case_sensitive = pid_case_sensitive

    def destroy(self) -> None:
        pass

    def get_ResourceInfos(self, pid: str) -> Optional[List[ResourceInfo]]:
        if pid is None:
            raise TypeError("pid is None")
        if pid.isspace():
            raise ValueError("pid is empty")

        if not self.pid_case_sensitive:
            pid = pid.lower()

        if pid == EndpointDescription.PID_ROOT:
            return self.entries
        else:
            ri = self.find_recursive(self.entries, pid)
            if ri:
                return ri.sub_Resources
        return None

    def find_recursive(
        self, items: Optional[List[ResourceInfo]], pid: str
    ) -> Optional[ResourceInfo]:
        if items:
            for item in items:
                if self.pid_case_sensitive:
                    if pid == item.pid:
                        return item
                else:
                    if pid.lower() == item.pid.lower():
                        return item
                if item.has_sub_Resources():
                    ri = self.find_recursive(item.sub_Resources, pid)
                    if ri:
                        return ri
        return None


# ---------------------------------------------------------------------------


class SimpleEndpointSearchEngineBase(
    SRUAuthenticationInfoProviderFactory, SRUSearchEngine, metaclass=ABCMeta
):
    """A base class for implementing a simple search engine to be
    used as a CLARIN-FCS endpoint."""

    def __init__(self) -> None:
        super().__init__()
        self.endpoint_description: Optional[EndpointDescription] = None

    # ----------------------------------------------------
    # non-overwritable (you really shouldn't)

    def init(
        self,
        config: SRUServerConfig,
        query_parser_registry_builder: SRUQueryParserRegistry.Builder,
        params: Dict[str, str],
    ) -> None:
        """This method should not be overridden. Perform your custom
        initialization in the `do_init` method instead.

        See also:
            `do_init`,
            `SRUSearchEngine.init`
        """
        LOGGER.debug("Initializing")
        super().init(config, query_parser_registry_builder, params)

        query_parser_registry_builder.register(FCSQueryParser())

        LOGGER.debug("Initializing search engine implementation")
        self.do_init(config, query_parser_registry_builder, params)

        LOGGER.debug("Initizalizing endpoint description")
        self.endpoint_description = self.create_EndpointDescription(
            config, query_parser_registry_builder, params
        )
        if not self.endpoint_description:
            LOGGER.error(
                "SimpleEndpointSearchEngineBase implementation error: "
                "create_EndpointDescription() returned None"
            )
            raise SRUConfigException(
                "create_EndpointDescription() returned no valid"
                " implementation of an EndpointDescription"
            )

    def destroy(self) -> None:
        """This method should not be overridden. Perform you custom
        cleanup in the `do_destroy` method.

        See also:
            `do_destroy`,
            `SRUSearchEngine.destroy`
        """
        LOGGER.debug("Performing cleanup of endpoint description")
        if self.endpoint_description:
            self.endpoint_description.destroy()

        LOGGER.debug("Performing cleanup of search engine")
        self.do_destroy()

        return super().destroy()

    def create_SRUAuthenticationInfoProvider(
        self, params: Dict[str, str]
    ) -> Optional[SRUAuthenticationInfoProvider]:
        enabled_str = params.get(FCSAuthenticationParam.ENABLE)
        if not enabled_str:
            return None
        enabled = SimpleEndpointSearchEngineBase._parse_bool(enabled_str)
        if not enabled:
            LOGGER.debug("Explictly disable authentication")
            return None

        LOGGER.debug("Enabling authentication")
        builder = AuthenticationProvider.Builder.create()

        audience = params.get(FCSAuthenticationParam.AUDIENCE)
        if audience:
            values = [v.strip() for v in audience.split(",") if v.strip()]
            if values:
                for value in values:
                    LOGGER.debug("Adding audience: %s", value)
                    builder.with_audience(value)

        ignore_IssuedAt = SimpleEndpointSearchEngineBase._parse_bool(
            params.get(FCSAuthenticationParam.IGNORE_ISSUEDAT)
        )
        if ignore_IssuedAt:
            LOGGER.debug("Will not verify 'iat' claim")
            builder.with_ignore_IssuedAt()
        else:
            leeway = SimpleEndpointSearchEngineBase._parse_int(
                params.get(FCSAuthenticationParam.ACCEPT_ISSUEDAT), -1
            )
            if leeway > 0:
                LOGGER.debug("Allowing %s seconds leeway for 'iat' claim", leeway)
                builder.with_IssuedAt(leeway)

        leeway = SimpleEndpointSearchEngineBase._parse_int(
            params.get(FCSAuthenticationParam.ACCEPT_EXPIRESAT), -1
        )
        if leeway > 0:
            LOGGER.debug("Allowing %s seconds leeway for 'exp' claim", leeway)
            builder.with_ExpiresAt(leeway)

        leeway = SimpleEndpointSearchEngineBase._parse_int(
            params.get(FCSAuthenticationParam.ACCEPT_NOTBEFORE), -1
        )
        if leeway > 0:
            LOGGER.debug("Allowing %s seconds leeway for 'nbf' claim", leeway)
            builder.with_NotBefore(leeway)

        # load keys
        for name, value in params.items():
            if not name.startswith(FCSAuthenticationParam.PUBLIC_KEY_PREFIX):
                continue
            key_id = name[len(FCSAuthenticationParam.PUBLIC_KEY_PREFIX.value) :].strip()
            if not key_id:
                raise SRUConfigException(
                    f"init-parameter: '{name}' is invalid: key_id is empty!"
                )
            # key_filename = value
            LOGGER.debug("key_id = %s, key_file = %s", key_id, value)
            if value.startswith(RESOURCE_URI_PREFIX):
                LOGGER.debug("Loading key '%s' from resource '%s'", key_id, value)
                key = self._load_key_from_resource(value[len(RESOURCE_URI_PREFIX) :])
                builder.with_public_key(key_id, key)
            else:
                LOGGER.debug("Loading key '%s' from file '%s'", key_id, value)
                # NOTE: value is a filepath
                builder.with_public_key(key_id, value)

        auth_provider = builder.build()
        if auth_provider.key_count == 0:
            LOGGER.warning(
                "No keys configured, all well-formed tokens will be"
                " accepted. Make sure, youn know what you are doing!"
            )
        return auth_provider

    def _load_key_from_resource(self, path: str) -> bytes:
        package, name = path.split(":")

        if not importlib.resources.is_resource(package, name):
            raise SRUConfigException(f"Cannot open '{name}' in '{package}'")

        with importlib.resources.open_binary(package, name) as fp:
            return fp.read()

    # ----------------------------------------------------

    def explain(
        self,
        config: SRUServerConfig,
        request: SRURequest,
        diagnostics: SRUDiagnosticList,
    ) -> Optional[SRUExplainResult]:
        val = request.get_extra_request_data(X_FCS_ENDPOINT_DESCRIPTION)
        provide_epdesc = SimpleEndpointSearchEngineBase._parse_bool(val)

        if provide_epdesc and self.endpoint_description:

            class SRUExplainResultWithEndpointDescription(SRUExplainResult):
                def __init__(
                    self,
                    diagnostics: SRUDiagnosticList,
                    endpoint_description: EndpointDescription,
                ) -> None:
                    super().__init__(diagnostics)
                    self.endpoint_description = endpoint_description

                @property
                def has_extra_response_data(self) -> bool:
                    return True

                def write_extra_response_data(self, writer: SRUXMLStreamWriter) -> None:
                    SimpleEndpointSearchEngineBase._write_EndpointDescription(
                        writer, self.endpoint_description
                    )

            return SRUExplainResultWithEndpointDescription(
                diagnostics, self.endpoint_description
            )

        return None

    def scan(
        self,
        config: SRUServerConfig,
        request: SRURequest,
        diagnostics: SRUDiagnosticList,
    ) -> Optional[SRUScanResultSet]:
        """Handle a **scan** operation. This implementation provides
        support to CLARIN FCS resource enumeration. If you want to
        provide custom scan behavior for a different index, override
        the `do_scan` method.
        """
        return self.do_scan(config, request, diagnostics)

    # ----------------------------------------------------
    # overwritable (can/should be overwritten)

    @abstractmethod
    def create_EndpointDescription(
        self,
        config: SRUServerConfig,
        query_parser_registry_builder: SRUQueryParserRegistry.Builder,
        params: Dict[str, str],
    ) -> EndpointDescription:
        pass

    @abstractmethod
    def do_init(
        self,
        config: SRUServerConfig,
        query_parser_registry_builder: SRUQueryParserRegistry.Builder,
        params: Dict[str, str],
    ) -> None:
        """Initialize the search engine. This initialization should
        be tailed towards your environment and needs.

        Args:
            config: the `SRUServerConfig` object for this search engine
            query_parser_registry_builder: the `SRUQueryParserRegistry.Builder`
                object to be used for this search engine. Use to register
                additional query parsers with the `SRUServer`
            params: additional parameters from the server configuration

        Raises:
            SRUConfigException: if an error occurred
        """

    def do_destroy(self) -> None:
        """Destroy the search engine. Override this method for any
        cleanup the search engine needs to perform upon termination."""

    def do_scan(
        self,
        config: SRUServerConfig,
        request: SRURequest,
        diagnostics: SRUDiagnosticList,
    ) -> SRUScanResultSet:
        """[Deprecated]
        Handle a **scan** operation. The default implementation is
        a no-op. Override this method, if you want to provide a
        custom behavior.

        Args:
            config: the `SRUEndpointConfig` object that contains the
                endpoint configuration
            request: the `SRURequest` object that contains the
                request made to the endpoint
            diagnostics: the `SRUDiagnosticList` object for storing
                non-fatal diagnostics

        Returns:
            SRUScanResultSet: a `SRUScanResultSet` object or ``None``
                if this operation is not supported by this search
                engine

        Raises:
            `SRUException`: if an fatal error occurred
        """
        warnings.warn(
            "'do_scan' is deprecated. See Java implementation for more details?!",
            category=DeprecationWarning,
            stacklevel=2,
        )

        # not really sure what this does exactly, based on java implementation
        scan_clause = request.get_scan_clause()
        if not scan_clause:
            # NOTE: this should not happen?
            raise SRUException(
                SRUDiagnostics.GENERAL_SYSTEM_ERROR,
                message="Missing scan clause?",
            )
        elif (
            isinstance(scan_clause.root, cql.parser.CQLSearchClause)
            and scan_clause.root.index
        ):
            # CQLTermNode ?
            index = scan_clause.root.index.name
            raise SRUException(
                SRUDiagnostics.UNSUPPORTED_INDEX,
                index,
                message=f"scan operation on index '{index}' is not supported",
            )
        else:
            raise SRUException(
                SRUDiagnostics.QUERY_FEATURE_UNSUPPORTED,
                message="Scan clause too complex.",
            )

    # ----------------------------------------------------

    @staticmethod
    def _write_EndpointDescription(writer: ContentHandler, epdesc: EndpointDescription):
        writer = XMLStreamWriterHelper(writer)

        writer.startPrefixMapping(ED_PREFIX, ED_NS)
        writer.startElementNS(
            (ED_NS, "EndpointDescription"),
            attrs={"version": str(epdesc.get_version())},
        )

        # Capabilities
        with writer.element("Capabilities", ED_NS):
            for capability in epdesc.get_capabilities():
                with writer.element("Capability", ED_NS):
                    writer.characters(capability)

        # SupportedDataViews
        with writer.element("SupportedDataViews", ED_NS):
            for dataview in epdesc.get_supported_DataViews():
                if (
                    not dataview.deliveryPolicy
                    or dataview.deliveryPolicy not in DataView.DeliveryPolicy
                ):
                    raise SAXException(
                        f"invalid value for payload delivery policy: {dataview.deliveryPolicy}"
                    )
                with writer.element(
                    "SupportedDataView",
                    ED_NS,
                    attrs={
                        "id": dataview.identifier,
                        "delivery-policy": dataview.deliveryPolicy.value,
                    },
                ):
                    writer.characters(dataview.mimetype)

        # SupportedLayers (FCS 2.0)
        if epdesc.is_version(EndpointDescription.VERSION_2):
            if epdesc.get_supported_Layers():
                with writer.element("SupportedLayers", ED_NS):
                    for layer in epdesc.get_supported_Layers():
                        attrs = {"id": layer.id, "result-id": layer.result_id}
                        if layer.encoding == Layer.ContentEncoding.EMPTY:
                            attrs["type"] = "empty"
                        if layer.qualifier:
                            attrs["qualifier"] = layer.qualifier
                        if layer.alt_ValueInfo:
                            attrs["alt-value-info"] = layer.alt_ValueInfo
                            if layer.alt_ValueInfo_url:
                                attrs["alt-value-info-uri"] = layer.alt_ValueInfo_url
                        with writer.element("SupportedLayer", ED_NS, attrs=attrs):
                            writer.characters(layer.type)

        # Resources
        try:
            resources = epdesc.get_ResourceInfos(EndpointDescription.PID_ROOT)
            if not resources:
                raise SRUException("top level must contain resources")
            write_layers = epdesc.is_version(EndpointDescription.VERSION_2)
            SimpleEndpointSearchEngineBase._write_ResourceInfos(
                writer, resources, write_layers
            )
        except SRUException as ex:
            raise SAXException("error retriving top-level resources") from ex

        writer.endElementNS((ED_NS, "EndpointDescription"), None)
        writer.endPrefixMapping(ED_PREFIX)

    @staticmethod
    def _write_ResourceInfos(
        writer: ContentHandler, resources: List[ResourceInfo], write_layers: bool = True
    ):
        if resources is None:
            raise TypeError("resources is None")
        if not resources:
            return

        writer = XMLStreamWriterHelper(writer)

        # TODO: XML NS required or auto included/known?
        writer.startPrefixMapping(XML_NS_PREFIX, XML_NS_URI)
        writer.startElementNS((ED_NS, "Resources"))

        for resource in resources:
            writer.startElementNS((ED_NS, "Resource"), attrs={"pid": resource.pid})

            # title
            for lang, title in resource.title.items():
                with writer.element("Title", ED_NS, attrs={(XML_NS_URI, "lang"): lang}):
                    writer.characters(title)

            # description
            if resource.description:
                for lang, desc in resource.description.items():
                    with writer.element(
                        "Description", ED_NS, attrs={(XML_NS_URI, "lang"): lang}
                    ):
                        writer.characters(desc)

            # landing page
            if resource.landing_page_uri:
                with writer.element("LandingPageURI", ED_NS):
                    writer.characters(resource.landing_page_uri)

            # languages
            with writer.element("Languages", ED_NS):
                for language in resource.languages:
                    with writer.element("Language", ED_NS):
                        writer.characters(language)

            # available data views
            dvref = " ".join(dv.identifier for dv in resource.available_DataViews)
            writer.startElementNS((ED_NS, "AvailableDataViews"), attrs={"ref": dvref})
            writer.endElementNS((ED_NS, "AvailableDataViews"))

            # available layer (FCS 2.0)
            if write_layers and resource.available_Layers:
                lref = " ".join(ly.id for ly in resource.available_Layers)
                writer.startElementNS((ED_NS, "AvailableLayers"), attrs={"ref": lref})
                writer.endElementNS((ED_NS, "AvailableLayers"))

            # child resources
            subs = resource.sub_Resources
            if subs:
                SimpleEndpointSearchEngineBase._write_ResourceInfos(writer, subs)

            writer.endElementNS((ED_NS, "Resource"), None)

        writer.endElementNS((ED_NS, "Resources"), None)

    # ----------------------------------------------------

    @staticmethod
    def _parse_bool(val: Optional[str]) -> bool:
        """Convince method for parsing a string to boolean. Values
        ``1``, ``true`` and ``yes`` yield a ``True`` boolean value
        as a result, all others (include ``None``) a ``False``
        boolean value.

        Args:
            val: the string to parse

        Returns:
            bool: ``True`` if the supplied string was considered something representing a ``True`` boolean value, ``False`` otherwise
        """
        if not val:
            return False
        val = val.strip().lower()
        if not val:
            return False
        return val in ("true", "1", "yes")

    @staticmethod
    def _parse_int(val: Optional[str], default: int) -> int:
        if not val or val.isspace():
            return default
        try:
            return int(val)
        except ValueError:
            raise SRUConfigException("invalid long value")


# ---------------------------------------------------------------------------
