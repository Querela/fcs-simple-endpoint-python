import io
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import TextIO
from typing import Union
from urllib.parse import urlparse

from clarin.sru.exception import SRUConfigException
from lxml import etree

from clarin.sru.fcs.constants import ED_NS
from clarin.sru.fcs.constants import ED_PREFIX
from clarin.sru.fcs.constants import LANG_EN
from clarin.sru.fcs.constants import LAYER_TYPE_EXTENSION_PREFIX
from clarin.sru.fcs.constants import RI_NS_LEGACY
from clarin.sru.fcs.constants import XML_NS_URI
from clarin.sru.fcs.constants import Capabilities
from clarin.sru.fcs.constants import FCSDataViewNamespaces
from clarin.sru.fcs.constants import FCSLayerType
from clarin.sru.fcs.server.search import DataView
from clarin.sru.fcs.server.search import EndpointDescription
from clarin.sru.fcs.server.search import Layer
from clarin.sru.fcs.server.search import ResourceInfo
from clarin.sru.fcs.server.search import SimpleEndpointDescription

# ---------------------------------------------------------------------------


LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------


class SimpleEndpointDescriptionParser:
    """A parser, that parses an XML file and produces a endpoint
    description with static list of resource info records. The XML
    file has the same format as the result format defined for
    endpoint description of the CLARIN-FCS specification. The `parse`
    returns a `SimpleEndpointDescription` instance."""

    @staticmethod
    def parse(url: Union[str, TextIO]) -> EndpointDescription:
        """Parse an XML file and return a static list of resource
        info records.

        Args:
            url: the URI pointing to the file to be parsed

        Returns:
            EndpointDescription: an `EndpointDescription` instance

        Raises:
            SRUConfigException: if an error occurred
            TypeError: if url is None
        """
        if url is None:
            raise TypeError("url is None")

        LOGGER.debug("Parsing endpoint description from: %s", url)

        try:
            parser = etree.XMLParser(
                ns_clean=False, remove_comments=True, strip_cdata=True
            )
            ed_doc: etree._ElementTree = etree.parse(url, parser)

            # TODO: validate with schema? (like fcs-sru-server config?)

            # Detect for deprecated resource-info catalog files and bail, if necessary
            # url.name if isinstance(url, io.TextIOWrapper) else url ?
            SimpleEndpointDescriptionParser._check_legacy_mode(ed_doc, url)

            # Parse on and create endpoint description ...
            return SimpleEndpointDescriptionParser._parse_EndpointDescription(ed_doc)
        except etree.XPathEvalError as ex:
            raise SRUConfigException("internal error") from ex
        except etree.XMLSyntaxError as ex:
            raise SRUConfigException("parsing error") from ex
        except SRUConfigException:
            raise
        except OSError as ex:
            raise SRUConfigException("error reading file") from ex
        except Exception as ex:
            raise SRUConfigException("internal error") from ex
        # lxml ParserConfigurationException ?

    # ----------------------------------------------------

    @staticmethod
    def _parse_EndpointDescription(doc: etree._ElementTree) -> EndpointDescription:
        version = SimpleEndpointDescriptionParser._parse_version(doc)
        LOGGER.debug("Endpoint description version is %s", version)

        capabilities = SimpleEndpointDescriptionParser._parse_Capabilities(doc)
        LOGGER.debug("CAPS: %s", capabilities)
        SimpleEndpointDescriptionParser._check_Capabilities(capabilities, version)

        xml_ids: Set[str] = set()  # used to check for uniqueness of id attribute
        supported_DataViews = SimpleEndpointDescriptionParser._parse_DataViews(
            doc, xml_ids
        )
        LOGGER.debug("DV: %s", supported_DataViews)
        SimpleEndpointDescriptionParser._check_DataViews(
            supported_DataViews, capabilities
        )

        supported_Layers = SimpleEndpointDescriptionParser._parse_Layers(doc, xml_ids)
        LOGGER.debug("L: %s", supported_Layers)
        SimpleEndpointDescriptionParser._check_Layers(supported_Layers, capabilities)

        resources = SimpleEndpointDescriptionParser._parse_ResourceInfos(
            doc, supported_DataViews, supported_Layers, version
        )
        if not resources:
            raise SRUConfigException(
                "No resources where defined in endpoint description"
            )
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug("Dumping ResourceInfo:")
            SimpleEndpointDescriptionParser._dump_ResourceInfo(resources, 1)

        return SimpleEndpointDescription(
            version,
            capabilities,
            supported_DataViews,
            supported_Layers,
            resources,
            False,
        )

    # ----------------------------------------------------

    @staticmethod
    def _parse_version(doc: etree._ElementTree) -> int:
        version = -1
        nodes = doc.xpath(
            "//ed:EndpointDescription/@version", namespaces={ED_PREFIX: ED_NS}
        )
        if nodes:
            try:
                version = int(nodes[0])
                if version not in (1, 2):
                    raise SRUConfigException(
                        "Attribute @version element <EndpointDescription> must have a value of either '1' or '2'"
                    )
            except ValueError as ex:
                raise SRUConfigException("Cannot parse version number") from ex
        if version == -1:
            raise SRUConfigException(
                "Attribute @version missing on element <EndpointDescription>"
            )
        return version

    @staticmethod
    def _parse_Capabilities(doc: etree._ElementTree) -> List[str]:
        capabilities: List[str] = list()
        nodes = doc.xpath(
            "//ed:Capabilities/ed:Capability", namespaces={ED_PREFIX: ED_NS}
        )
        if nodes:
            LOGGER.debug("Parsing capabilities")
            for node in nodes:
                uri = node.text.strip()
                try:
                    urlparse(uri)
                except Exception:
                    raise SRUConfigException(
                        f"capability is not encoded as a proper URI: {uri}"
                    )
                if uri not in capabilities:
                    capabilities.append(uri)
                else:
                    LOGGER.warning("Ignoring duplicate capability entry for '%s'.", uri)

        else:
            LOGGER.warning("No capabilities where defined in endpoint configuration.")

        return capabilities

    @staticmethod
    def _check_Capabilities(capabilities: List[str], version: int):
        if Capabilities.BASIC_SEARCH not in capabilities:
            LOGGER.warning(
                "Capability '%s' was not defined in endpoint description;"
                " it was added to meet the specification. Please update your"
                " endpoint description!",
                Capabilities.BASIC_SEARCH,
            )
            capabilities.append(Capabilities.BASIC_SEARCH)

        if Capabilities.ADVANCED_SEARCH in capabilities and version < 2:
            LOGGER.warning(
                "Endpoint description is declared as version FCS 1.0 (@version = 1),"
                " but contains support for Advanced Search in capabilities list!"
                " FCS 1.0 only supports Basic Search."
            )

    @staticmethod
    def _parse_DataViews(doc: etree._ElementTree, xml_ids: Set[str]) -> List[DataView]:
        nodes = doc.xpath(
            "//ed:SupportedDataViews/ed:SupportedDataView",
            namespaces={ED_PREFIX: ED_NS},
        )
        if not nodes:
            LOGGER.error(
                "Endpoint configuration contains no valid information about supported data views"
            )
            raise SRUConfigException(
                "Endpoint configuration contains no valid information about supported data views"
            )

        dataviews: List[DataView] = list()
        LOGGER.debug("Parsing supported data views")
        for node in nodes:
            id = SimpleEndpointDescriptionParser._get_attribute(node, "id")
            if id is None:
                raise SRUConfigException(
                    "Element <SupportedDataView> must have a proper 'id' attribute"
                )

            if id in xml_ids:
                raise SRUConfigException(
                    f"The value of attribute 'id' of element <SupportedDataView> must be unique: {id}"
                )
            xml_ids.add(id)

            # TODO: refactor as constants?
            pval = SimpleEndpointDescriptionParser._get_attribute(
                node, "delivery-policy"
            )
            if pval is None:
                raise SRUConfigException(
                    "Element <SupportedDataView> must have a 'delivery-policy' attribute"
                )
            policy: DataView.DeliveryPolicy
            if DataView.DeliveryPolicy.SEND_BY_DEFAULT == pval:
                policy = DataView.DeliveryPolicy.SEND_BY_DEFAULT
            elif DataView.DeliveryPolicy.NEED_TO_REQUEST == pval:
                policy = DataView.DeliveryPolicy.NEED_TO_REQUEST
            else:
                raise SRUConfigException(
                    f"Invalid value '{pval}' for attribute 'delivery-policy' on element <SupportedDataView>"
                )

            mimetype: Optional[str] = node.text
            if mimetype:
                mimetype = mimetype.strip()
                if not mimetype:
                    mimetype = None
            if not mimetype:
                raise SRUConfigException(
                    "Element <SupportedDataView> must contain a MIME-type as content"
                )

            # check for duplicate entries ...
            for dataview in dataviews:
                if id == dataview.identifier:
                    raise SRUConfigException(
                        f"A <SupportedDataView> with the id '{id}' is already defined!"
                    )
                if mimetype == dataview.mimetype:
                    raise SRUConfigException(
                        f"A <SupportedDataView> with the MIME-type '{mimetype}' is already defined!"
                    )

            dataviews.append(
                DataView(identifier=id, mimetype=mimetype, deliveryPolicy=policy)
            )

        return dataviews

    @staticmethod
    def _check_DataViews(dataviews: List[DataView], capabilities: List[str]):
        # sanity check on data views
        has_HITS_view = has_ADV_view = False
        for dataview in dataviews:
            if dataview.mimetype == FCSDataViewNamespaces.HITS.mimetype:
                has_HITS_view = True
            elif dataview.mimetype == FCSDataViewNamespaces.ADV.mimetype:
                has_ADV_view = True
        if not has_HITS_view:
            raise SRUConfigException(
                f"Generic Hits Data View ({FCSDataViewNamespaces.HITS.mimetype})"
                " was not declared in <SupportedDataViews>"
            )
        if Capabilities.ADVANCED_SEARCH in capabilities and not has_ADV_view:
            raise SRUConfigException(
                "Endpoint claimes to support Advanced FCS but does not declare"
                f" Advanced Data View ({FCSDataViewNamespaces.ADV.mimetype})"
                "in <SupportedDataViews>"
            )

    @staticmethod
    def _parse_Layers(doc: etree._ElementTree, xml_ids: Set[str]) -> List[Layer]:
        layers: List[Layer] = list()
        nodes = doc.xpath(
            "//ed:SupportedLayers/ed:SupportedLayer",
            namespaces={ED_PREFIX: ED_NS},
        )
        if nodes:
            LOGGER.debug("Parsing supported layers")
            for node in nodes:
                id = SimpleEndpointDescriptionParser._get_attribute(node, "id")
                if id is None:
                    raise SRUConfigException(
                        "Element <SupportedLayer> must have a proper 'id' attribute"
                    )

                if id in xml_ids:
                    raise SRUConfigException(
                        f"The value of attribute 'id' of element <SupportedLayer> must be unique: {id}"
                    )
                xml_ids.add(id)

                # TODO: refactor as constants?
                result_id = SimpleEndpointDescriptionParser._get_attribute(
                    node, "result-id"
                )
                if result_id is None:
                    raise SRUConfigException(
                        "Element <SupportedLayer> must have a 'result-id' attribute"
                    )
                try:
                    urlparse(result_id)
                except Exception:
                    raise SRUConfigException(
                        "Attribute 'result-id' on Element <SupportedLayer>"
                        f" is not encoded as proper URI: {result_id}"
                    )

                rtype = SimpleEndpointDescriptionParser._clean_str(node.text)
                if not rtype:
                    raise SRUConfigException(
                        "Element <SupportedLayer> does not define a proper layer type"
                    )
                # sanity check on layer types
                if rtype not in [
                    lt.value for lt in FCSLayerType
                ] and not rtype.startswith(LAYER_TYPE_EXTENSION_PREFIX):
                    LOGGER.warning(
                        "layer type '%s' is not defined by specification", rtype
                    )

                qualifier = SimpleEndpointDescriptionParser._get_attribute(
                    node, "qualifier"
                )

                encoding = Layer.ContentEncoding.VALUE
                eval = SimpleEndpointDescriptionParser._get_attribute(node, "type")
                if eval:
                    if Layer.ContentEncoding.VALUE == eval:
                        encoding = Layer.ContentEncoding.VALUE
                    elif Layer.ContentEncoding.EMPTY == eval:
                        encoding = Layer.ContentEncoding.EMPTY
                    else:
                        raise SRUConfigException(f"Invalid layer encoding: {eval}")

                alt_value_info = SimpleEndpointDescriptionParser._get_attribute(
                    node, "alt-value-info"
                )
                alt_value_info_uri: Optional[str] = None
                if alt_value_info:
                    alt_value_info_uri = SimpleEndpointDescriptionParser._get_attribute(
                        node, "alt-value-info-uri"
                    )
                    try:
                        urlparse(alt_value_info_uri)
                    except Exception:
                        raise SRUConfigException(
                            "Attribute 'alt-value-info-uri' on Element <SupportedLayer>"
                            f" is not encoded as proper URI: {alt_value_info_uri}"
                        )

                layers.append(
                    Layer(
                        id=id,
                        result_id=result_id,
                        type=rtype,
                        encoding=encoding,
                        qualifier=qualifier,
                        alt_ValueInfo=alt_value_info,
                        alt_ValueInfo_url=alt_value_info_uri,
                    )
                )

        return layers

    @staticmethod
    def _check_Layers(layers: List[Layer], capabilities: List[str]):
        if layers and Capabilities.ADVANCED_SEARCH not in capabilities:
            LOGGER.warning(
                "Endpoint description has <SupportedLayer> but does not indicate"
                " support for Advanced Search. Please consider adding capability"
                " (%s) to your endpoint description to make use of layers!",
                Capabilities.ADVANCED_SEARCH,
            )

    @staticmethod
    def _parse_ResourceInfos(
        doc: etree._ElementTree,
        supported_DataViews: List[DataView],
        supported_Layers: List[Layer],
        version: int,
    ) -> List[ResourceInfo]:
        pids: Set[str] = set()
        has_ADV_view = any(
            dataview.mimetype == FCSDataViewNamespaces.ADV.mimetype
            for dataview in supported_DataViews
        )

        def _parse_resources(nodes) -> List[ResourceInfo]:
            if not nodes:
                return list()

            resources: List[ResourceInfo] = list()
            for node in nodes:
                titles: Dict[str, str] = dict()
                descrs: Dict[str, str] = dict()
                link: Optional[str] = None
                langs: List[str] = list()
                availDataViews: List[DataView] = list()
                availLayers: List[Layer] = list()
                sub: List[ResourceInfo] = list()

                pid = SimpleEndpointDescriptionParser._get_attribute(node, "pid")
                if pid is None:
                    raise SRUConfigException(
                        "Element <ResourceInfo> must have a proper 'pid' attribute"
                    )
                if pid in pids:
                    raise SRUConfigException(
                        f"Another element <Resource> with pid '{pid}' already exists"
                    )
                pids.add(pid)
                LOGGER.debug("Processing resource with pid '%s'", pid)

                for tnode in node.xpath("ed:Title", namespaces={ED_PREFIX: ED_NS}):
                    lang = SimpleEndpointDescriptionParser._get_lang_attribute(tnode)
                    if not lang:
                        raise SRUConfigException(
                            "Element <Title> must have a proper 'xml:lang' attribute"
                        )

                    title = SimpleEndpointDescriptionParser._clean_str(tnode.text)
                    if not title:
                        # NOTE: in java code confusing error message
                        raise SRUConfigException(
                            "Element <Title> must not be non-empty"
                        )
                    if lang in titles:
                        LOGGER.warning("Title with language '%s' already exists", lang)
                    else:
                        LOGGER.debug("title: '%s' '%s'", lang, title)
                        titles[lang] = title
                if titles and LANG_EN not in titles:
                    raise SRUConfigException(
                        "A <Title> with language 'en' is mandatory"
                    )

                for dnode in node.xpath(
                    "ed:Description", namespaces={ED_PREFIX: ED_NS}
                ):
                    lang = SimpleEndpointDescriptionParser._get_lang_attribute(dnode)
                    if not lang:
                        raise SRUConfigException(
                            "Element <Description> must have a proper 'xml:lang' attribute"
                        )

                    descr = SimpleEndpointDescriptionParser._clean_str(dnode.text)

                    if lang in descrs:
                        LOGGER.warning("Title with language '%s' already exists", lang)
                    else:
                        LOGGER.debug("description: '%s' '%s'", lang, descr)
                        # NOTE: skip if None? - java impl would allow nulls
                        if not descr:
                            LOGGER.debug("Skip empty description for lang '%s'", lang)
                        else:
                            descrs[lang] = descr
                if descrs and LANG_EN not in descrs:
                    raise SRUConfigException(
                        "A <Description> with language 'en' is mandatory"
                    )

                for lnode in node.xpath(
                    "ed:LandingPageURI", namespaces={ED_PREFIX: ED_NS}
                ):
                    # TODO: only keep last one? (in java impl)
                    link = SimpleEndpointDescriptionParser._clean_str(lnode.text)

                for lnode in node.xpath(
                    "ed:Languages/ed:Language", namespaces={ED_PREFIX: ED_NS}
                ):
                    val = lnode.text
                    if val:
                        val = val.strip()
                        if not val:
                            val = None

                    # enforce three letter codes
                    if val and len(val) != 3:
                        raise SRUConfigException(
                            "Element <Language> must use ISO-639-3 three letter language codes"
                        )

                    langs.append(val)

                dvnodes = node.xpath(
                    "ed:AvailableDataViews", namespaces={ED_PREFIX: ED_NS}
                )
                if not dvnodes:
                    raise SRUConfigException("Missing element <AvailableDataViews>")
                dvnode = dvnodes[0]
                ref = SimpleEndpointDescriptionParser._get_attribute(dvnode, "ref")
                if not ref:
                    raise SRUConfigException(
                        "Element <AvailableDataViews> must have a 'ref' attribute"
                    )
                refs = ref.split()
                if not refs:
                    raise SRUConfigException(
                        "Attribute 'ref' on element <AvailableDataViews> must contain"
                        " a whitespace seperated list of data view references"
                    )
                for ref in refs:
                    for dataview in supported_DataViews:
                        if ref == dataview.identifier:
                            availDataViews.append(dataview)
                            break
                    else:
                        raise SRUConfigException(
                            f"A data view with identifier '{ref}' was not"
                            " defined in <SupportedDataViews>"
                        )
                if not availDataViews:
                    raise SRUConfigException(
                        f"No available data views were defined for resource"
                        f" with PID '{pid}'"
                    )

                lnodes = node.xpath("ed:AvailableLayers", namespaces={ED_PREFIX: ED_NS})
                if lnodes:
                    lnode = lnodes[0]
                    ref = SimpleEndpointDescriptionParser._get_attribute(lnode, "ref")
                    if not ref:
                        raise SRUConfigException(
                            "Element <AvailableLayers> must have a 'ref' attribute"
                        )
                    refs = ref.split()
                    if not refs:
                        # NOTE: copy-paste error in java
                        raise SRUConfigException(
                            "Attribute 'ref' on element <AvailableLayers> must contain"
                            " a whitespace seperated list of layer references"
                        )
                    for ref in refs:
                        for layer in supported_Layers:
                            if ref == layer.id:
                                availLayers.append(layer)
                                break
                        else:
                            raise SRUConfigException(
                                f"A layer with identifier '{ref}' was not"
                                " defined in <SupportedLayers>"
                            )
                else:
                    if has_ADV_view:
                        LOGGER.debug("No <SupportedLayers> for resource '%s'", pid)

                rnodes = node.xpath(
                    "ed:Resources/ed:Resource", namespaces={ED_PREFIX: ED_NS}
                )
                sub = _parse_resources(rnodes)
                # TODO: None if empty?

                # NOTE: version check in java faulty?
                if availLayers and version <= 1:
                    LOGGER.warning(
                        "Endpoint claims to support FCS 1.0, but includes information"
                        " about <AvailableLayers> for resource with pid '%s'",
                        pid,
                    )

                resources.append(
                    ResourceInfo(
                        pid=pid,
                        title=titles,
                        description=descrs,
                        landing_page_uri=link,
                        languages=langs,
                        available_DataViews=availDataViews,
                        available_Layers=availLayers,
                        sub_Resources=sub,
                    )
                )

            return resources

        nodes = doc.xpath(
            "//ed:EndpointDescription/ed:Resources/ed:Resource",
            namespaces={ED_PREFIX: ED_NS},
        )
        resources: List[ResourceInfo] = _parse_resources(nodes)

        return resources

    # ----------------------------------------------------

    @staticmethod
    def _get_attribute(el: etree._Element, localname: str) -> Optional[str]:
        val: Optional[str] = el.get(localname)
        if val:
            val = val.strip()
            if not val.isspace():
                return val
        return None

    @staticmethod
    def _get_lang_attribute(el: etree._Element) -> Optional[str]:
        name = etree.QName(XML_NS_URI, "lang")
        return SimpleEndpointDescriptionParser._get_attribute(el, name)

    @staticmethod
    def _clean_str(val: str) -> Optional[str]:
        if val:
            val = val.strip()
            val = " ".join(val.split())
            if val:
                return val
        return None

    @staticmethod
    def _dump_ResourceInfo(ris: List[ResourceInfo], depth: int):
        pfx = "--" * depth
        for ri in ris:
            sris = ri.sub_Resources
            LOGGER.debug("%s %s (level=%s)", pfx, ri.pid, depth)
            if sris:
                SimpleEndpointDescriptionParser._dump_ResourceInfo(sris, depth + 1)

    @staticmethod
    def _check_legacy_mode(doc: etree._ElementTree, url: Union[str, TextIO]):
        try:
            if isinstance(url, io.TextIOWrapper) and url.name:
                url = url.name
        except Exception:
            pass
        root: etree.Element = doc.getroot()
        if root is None:
            raise SRUConfigException("Error retrieving root element")
        ns = root.xpath("namespace-uri()")
        if not ns:
            raise SRUConfigException(
                f"No namespace URI was detected for resource info catalog file '{url}'!"
            )
        if ns == RI_NS_LEGACY:
            LOGGER.error(
                f"Detected out-dated resource info catalog file '{url}'."
                "Please update to the current version."
            )
            raise SRUConfigException(f"unsupport file format: {ns}")
        if ns != ED_NS:
            LOGGER.error(
                f"Detected unsupported resource info catalog file '{url}'"
                f" with namespace '{ns}'."
            )
            raise SRUConfigException(f"unsupport file format: {ns}")


# ---------------------------------------------------------------------------
