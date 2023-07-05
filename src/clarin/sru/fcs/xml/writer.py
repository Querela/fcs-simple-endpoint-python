import warnings
from dataclasses import dataclass
from enum import Enum
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union
from xml.sax.handler import ContentHandler

from clarin.sru.xml.writer import XMLStreamWriterHelper

from clarin.sru.fcs.constants import FCS_NS
from clarin.sru.fcs.constants import FCS_PREFIX
from clarin.sru.fcs.constants import FCSDataViewNamespaces

# ---------------------------------------------------------------------------
# basic/HITS/KWIC dataview


class FCSRecordXMLStreamWriter:
    """This class provides several helper methods for writing records
    in the CLARIN-FCS record schema. These methods **do not** cover
    the full spectrum of all variations of records that are permitted
    by the CLARIN-FCS specification.

    See also:
        - CLARIN FCS specification, section "Operation searchRetrieve"
    """

    @staticmethod
    def startResource(
        writer: ContentHandler, pid: Optional[str] = None, ref: Optional[str] = None
    ) -> None:
        """Write the start of a resource (i.e. the ``<Resource>``
        element). Calls to this method need to be balanced with calls
        to the `endResource` method.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            pid: the persistent identifier of this resource or ``None``, if not applicable. Defaults to None.
            ref: the reference of this resource or ``None``, if not applicable. Defaults to None.
        """
        if writer is None:
            raise TypeError("writer is None")

        attrs = dict()
        if pid and not pid.isspace():
            attrs[(None, "pid")] = pid
        if ref and not ref.isspace():
            attrs[(None, "ref")] = ref

        writer.startPrefixMapping(FCS_PREFIX, FCS_NS)
        writer.startElementNS((FCS_NS, "Resource"), None, attrs)

    @staticmethod
    def endResource(writer: ContentHandler) -> None:
        """Write the end of a resource (i.e. the ``</Resource>``
        element). Calls to this method need to be balanced with calls
        to the `startResource` method.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
        """
        if writer is None:
            raise TypeError("writer is None")

        writer.endElementNS((FCS_NS, "Resource"), None)
        writer.endPrefixMapping(FCS_PREFIX)

    @staticmethod
    def startResourceFragment(
        writer: ContentHandler, pid: Optional[str] = None, ref: Optional[str] = None
    ) -> None:
        """Write the start of a resource fragment (i.e. the
        ``<ResourceFragment>`` element). Calls to this method need to
        be balanced with calls to the `endResourceFragment` method.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            pid: the persistent identifier of this resource or ``None``, if not applicable. Defaults to None.
            ref: the reference of this resource or ``None``, if not applicable. Defaults to None.
        """
        if writer is None:
            raise TypeError("writer is None")

        attrs = dict()
        if pid and not pid.isspace():
            attrs[(None, "pid")] = pid
        if ref and not ref.isspace():
            attrs[(None, "ref")] = ref

        writer.startElementNS((FCS_NS, "ResourceFragment"), None, attrs)

    @staticmethod
    def endResourceFragment(writer: ContentHandler) -> None:
        """Write the end of a resource fragment (i.e. the
        ``</ResourceFragment>`` element). Calls to this method need
        to be balanced with calls to the `startResourceFragment`
        method.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
        """
        if writer is None:
            raise TypeError("writer is None")

        writer.endElementNS((FCS_NS, "ResourceFragment"), None)

    @staticmethod
    def startDataView(writer: ContentHandler, mimetype: str) -> None:
        """Write the start of a data view (i.e. the ``<DataView>``
        element). Calls to this method need to be balanced with calls
        to the `endDataView` method.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            mimetype: the MIME type of this data view applicable
        """
        if writer is None:
            raise TypeError("writer is None")
        if mimetype is None:
            raise TypeError("mimetype is None")
        elif mimetype is None:
            raise ValueError("mimetype is empty")

        writer.startElementNS((FCS_NS, "DataView"), None, {(None, "type"): mimetype})

    @staticmethod
    def endDataView(writer: ContentHandler) -> None:
        """Write the end of a data view (i.e. the ``</DataView>``
        element). Calls to this method need to be balanced with calls
        to the `startDataView` method.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
        """
        if writer is None:
            raise TypeError("writer is None")

        writer.endElementNS((FCS_NS, "DataView"), None)

    # ----------------------------------------------------

    @staticmethod
    def writeKWICDataView(
        writer: ContentHandler, left: Optional[str], keyword: str, right: Optional[str]
    ) -> None:
        """[Deprecated] Use the HITS data view instead!
        Convince method to write a KWIC data view. It automatically
        performs the calls to `startDataView` and `endDataView`.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            left: the left context of the KWIC or ``None`` if not applicable
            keyword: the keyword of the KWIC
            right: the right context of the KWIC or ``None`` if not applicable
        """
        warnings.warn(
            "'writeKWICDataView' is deprecated. Use the HITS data view instead!",
            category=DeprecationWarning,
            stacklevel=2,
        )

        if writer is None:
            raise TypeError("writer is None")
        if keyword is None:
            raise TypeError("keyword is None")

        writer = XMLStreamWriterHelper(writer)
        ns = FCSDataViewNamespaces.KWIC

        FCSRecordXMLStreamWriter.startDataView(writer, ns.mimetype)

        # actual "kwic" data view
        with writer.prefix(ns.prefix, ns.namespace), writer.element(
            "kwic", ns.namespace
        ):
            with writer.element("c", ns.namespace, attrs={"type": "left"}):
                if left:
                    writer.characters(left)

            with writer.element("kw", ns.namespace):
                writer.characters(keyword)

            with writer.element("c", ns.namespace, {"type": "right"}):
                if right:
                    writer.characters(right)

        FCSRecordXMLStreamWriter.endDataView(writer)

    # ----------------------------------------------------

    @staticmethod
    def writeSingleHitHitsDataView(
        writer: ContentHandler, left: Optional[str], hit: str, right: Optional[str]
    ) -> None:
        """Convince method to write a simple HITS data view. It
        automatically performs the calls to `startDataView` and
        `endDataView`.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            left: the left context of the hit or ``None`` if not applicable
            hit: the actual hit, that will be highlighted
            right: the right context of the hit or ``None`` if not applicable
        """
        if writer is None:
            raise TypeError("writer is None")
        if hit is None:
            raise TypeError("hit is None")

        writer = XMLStreamWriterHelper(writer)
        ns = FCSDataViewNamespaces.HITS

        FCSRecordXMLStreamWriter.startDataView(writer, ns.mimetype)

        # actual "hits" data view
        with writer.prefix(ns.prefix, ns.namespace), writer.element(
            "Result", ns.namespace
        ):
            if left and not left.isspace():
                writer.characters(left)
            with writer.element("Hit", ns.namespace):
                writer.characters(hit)
            if right and not right.isspace():
                writer.characters(right)

        FCSRecordXMLStreamWriter.endDataView(writer)

    @staticmethod
    def writeHitsDataView(
        writer: ContentHandler,
        text: str,
        hits: List[Tuple[int, int]],
        second_is_length: bool,
    ) -> None:
        """Convince method to write a simple HITS data view. It
        automatically performs the calls to `startDataView` and
        `endDataView`.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            text: the text content of the hit
            hits: a list containing tuples (of start offsets, end offset/length) for the hit markers in the ``text`` content
            second_is_length: if ``True`` the second element of each tuple in this ``hits`` array is interpreted as an length; if ``False`` it is interpreted as an end-offset
        """
        if writer is None:
            raise TypeError("writer is None")
        if text is None:
            raise TypeError("text is None")
        if hits is None:
            raise TypeError("hits is None")
        if not hits or not all(isinstance(e, tuple) and len(e) == 2 for e in hits):
            raise ValueError("hits is empty or not all elements are 2-tuples")

        writer = XMLStreamWriterHelper(writer)
        ns = FCSDataViewNamespaces.HITS

        FCSRecordXMLStreamWriter.startDataView(writer, ns.mimetype)

        # actual "hits" data view
        with writer.prefix(ns.prefix, ns.namespace), writer.element(
            "Result", ns.namespace
        ):
            pos = 0
            for start, end in hits:
                if start < 0 or start > len(text):
                    raise ValueError(f"start index out of bounds: {start=}")
                if second_is_length:
                    if end < 1:
                        raise ValueError(f"length must be larger than 0: length={end}")
                    end += start
                if start >= end:
                    raise ValueError(
                        f"end offset must be larger then start offset: {start=}, {end=}"
                    )

                if start > pos:
                    writer.characters(text[pos:start])

                writer.elementcontent("Hit", text[start:end], ns.namespace)
                pos = end

            if pos < len(text) - 1:
                writer.characters(text[pos:])

        FCSRecordXMLStreamWriter.endDataView(writer)

    # ----------------------------------------------------

    @staticmethod
    def writeResourceWithSingleHitHitsDataView(
        writer: ContentHandler,
        pid: Optional[str],
        ref: Optional[str],
        left: Optional[str],
        hit: str,
        right: Optional[str],
    ):
        """Convince method to write a simple HITS data view. It
        automatically performs the calls to `startResource` and
        `endResource`.

        The following code (arguments omitted) would accomplish the
        same result::

            ...
            FCSRecordXMLStreamWriter.startResource(...)
            FCSRecordXMLStreamWriter.writeSingleHitHitsDataView(...)
            FCSRecordXMLStreamWriter.endResource(...)
            ...

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            pid: the persistent identifier of this resource or ``None``, if not applicable.
            ref: the reference of this resource or ``None``, if not applicable.
            left: the left context of the hit or ``None`` if not applicable
            hit: the actual hit, that will be highlighted
            right: the right context of the hit or ``None`` if not applicable

        Raises:
            TypeError: if writer is None
        """
        if writer is None:
            raise TypeError("writer is None")

        FCSRecordXMLStreamWriter.startResource(writer, pid=pid, ref=ref)
        FCSRecordXMLStreamWriter.writeSingleHitHitsDataView(
            writer, left=left, hit=hit, right=right
        )
        FCSRecordXMLStreamWriter.endResource(writer)

    @staticmethod
    def writeResourceWithHitsDataView(
        writer: ContentHandler,
        pid: Optional[str],
        ref: Optional[str],
        text: str,
        hits: List[Tuple[int, int]],
        second_is_length: bool,
    ):
        """Convince method to write a simple HITS data view. It
        automatically performs the calls to `startResource` and
        `endResource`.

        The following code (arguments omitted) would accomplish the
        same result::

            ...
            FCSRecordXMLStreamWriter.startResource(...)
            FCSRecordXMLStreamWriter.writeHitsDataView(...)
            FCSRecordXMLStreamWriter.endResource(...)
            ...

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            pid: the persistent identifier of this resource or ``None``, if not applicable.
            ref: the reference of this resource or ``None``, if not applicable.
            text: the text content of the hit
            hits: a list containing tuples (of start offsets, end offset/length) for the hit markers in the ``text`` content
            second_is_length: if ``True`` the second element of each tuple in this ``hits`` array is interpreted as an length; if ``False`` it is interpreted as an end-offset

        Raises:
            TypeError: if writer is None
        """
        if writer is None:
            raise TypeError("writer is None")

        FCSRecordXMLStreamWriter.startResource(writer, pid=pid, ref=ref)
        FCSRecordXMLStreamWriter.writeHitsDataView(
            writer, text=text, hits=hits, second_is_length=second_is_length
        )
        FCSRecordXMLStreamWriter.endResource(writer)

    @staticmethod
    def writeResourceWithKWICDataView(
        writer: ContentHandler,
        pid: Optional[str],
        ref: Optional[str],
        left: Optional[str],
        keyword: str,
        right: Optional[str],
    ) -> None:
        """[Deprecated]
        Convince method for writing a record with a KWIC data view.

        The following code (arguments omitted) would accomplish the
        same result::

            ...
            FCSRecordXMLStreamWriter.startResource(...)
            FCSRecordXMLStreamWriter.writeKWICDataView(...)
            FCSRecordXMLStreamWriter.endResource(...)
            ...

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            pid: the persistent identifier of this resource or ``None``, if not applicable.
            ref: the reference of this resource or ``None``, if not applicable.
            left: the left context of the KWIC or ``None`` if not applicable
            keyword: the keyword of the KWIC
            right: the right context of the KWIC or ``None`` if not applicable

        Note:
            Only use, if you want compatability to legacy FCS applications.
        """
        if writer is None:
            raise TypeError("writer is None")

        FCSRecordXMLStreamWriter.startResource(writer, pid=pid, ref=ref)
        FCSRecordXMLStreamWriter.writeKWICDataView(
            writer, left=left, keyword=keyword, right=right
        )
        FCSRecordXMLStreamWriter.endResource(writer)

    @staticmethod
    def writeResourceWithHitsDataViewLegacy(
        writer: ContentHandler,
        pid: Optional[str],
        ref: Optional[str],
        left: Optional[str],
        hit: str,
        right: Optional[str],
    ) -> None:
        """[Deprecated]
        Convince method for writing a record with a HITS and a
        KWIC data view. This method is intended for applications that
        want ensure computability to legacy CLARIN-FCS clients.

        The following code (arguments omitted) would accomplish the
        same result::

            ...
            FCSRecordXMLStreamWriter.startResource(...)
            FCSRecordXMLStreamWriter.writeSingleHitHitsDataView(...)
            FCSRecordXMLStreamWriter.writeKWICDataView(...)
            FCSRecordXMLStreamWriter.endResource(...)
            ...

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            pid: the persistent identifier of this resource or ``None``, if not applicable.
            ref: the reference of this resource or ``None``, if not applicable.
            left: the left context of the hit or ``None`` if not applicable
            hit: the actual hit, that will be highlighted
            right: the right context of the hit or ``None`` if not applicable

        Note:
            Only use, if you want compatability to legacy FCS applications.
        """
        if writer is None:
            raise TypeError("writer is None")

        FCSRecordXMLStreamWriter.startResource(writer, pid=pid, ref=ref)
        FCSRecordXMLStreamWriter.writeSingleHitHitsDataView(
            writer, left=left, hit=hit, right=right
        )
        FCSRecordXMLStreamWriter.writeKWICDataView(
            writer, left=left, keyword=hit, right=right
        )
        FCSRecordXMLStreamWriter.endResource(writer)


# ---------------------------------------------------------------------------
# ADV dataview


INITIAL_SEGMENT_ID = -1
NO_HIGHLIGHT = -1


class SpanOffsetUnit(str, Enum):
    ITEM = "item"
    TIMESTAMP = "timestamp"


@dataclass(eq=True)  # (frozen=True)
class Segment:
    id: Union[str, int]
    start: int
    end: int
    # FIXME: add API to set reference
    ref: Optional[str] = None

    def __post_init__(self):
        # object.__setattr__(self, "id", f"s{self.id:x}")
        if isinstance(self.id, int):
            self.id = f"s{self.id:x}"


@dataclass
class Span:
    segment: Segment
    value: Optional[str]
    altValue: Optional[str]
    highlight: Optional[Union[str, int]]

    def __post_init__(self):
        # object.__setattr__(self, "highlight", f"h{self.highlight:x}")
        if self.highlight is not None and isinstance(self.highlight, int):
            if self.highlight != NO_HIGHLIGHT:
                self.highlight = f"h{self.highlight:x}"
            else:
                self.highlight = None


class AdvancedDataViewWriter:
    """Helper class for serializing Advanced Data Views. It can be
    used for writing more than once, but it is **not thread-save**.
    This helper can also serialize HITS Data Views.
    """

    def __init__(self, unit: SpanOffsetUnit) -> None:
        """[Constructor]

        Args:
            unit: the unit to be used for span offsets

        Raises:
            TypeError: if unit is None
        """
        if unit is None:
            raise TypeError("unit is None")
        self.unit = unit
        """the unit to be used for span offsets"""
        self.next_segment_id = INITIAL_SEGMENT_ID
        self.segments: List[Segment] = list()
        self.layers: Dict[str, List[Span]] = dict()

    def reset(self):
        """Reset the writer for writing a new data view (instance)."""
        self.next_segment_id = INITIAL_SEGMENT_ID

    def addSpan(
        self,
        layer_id: str,
        start: int,
        end: int,
        value: Optional[str] = None,
        altValue: Optional[str] = None,
        highlight: Optional[int] = NO_HIGHLIGHT,
    ):
        """Add a span.

        Args:
            layer_id: the span's layer id
            start: the span's start offset
            end: the span's end offset
            value: the span's content value or ``None``
            altValue: the span's alternate value or ``None``
            highlight: the span's alternate value or ``None``
        """
        if layer_id is None:
            raise TypeError("layer_id is None")
        if start < 0:
            raise ValueError("start < 0")
        if end < start:
            raise ValueError("end < start")

        if highlight is None or highlight <= 0:
            highlight = NO_HIGHLIGHT

        # find segment or create a new one
        segment: Segment
        for seg in self.segments:
            if seg.start == start and seg.end == end:
                segment = seg
                break
        else:
            # if not segment:
            segment = Segment(self.next_segment_id, start, end)
            self.segments.append(segment)
            self.next_segment_id += 1

        # find layer or create a new one
        layer: Optional[List[Span]] = self.layers.get(layer_id, None)
        if layer is None:
            layer = list()
            self.layers[layer_id] = layer

        # sanity check (better overlap check?)
        for span in layer:
            if segment == span.segment:
                # FIXME: better exception!
                raise ValueError("segment already exists in layer")
        layer.append(Span(segment, value, altValue, highlight))

    # ----------------------------------------------------

    def writeAdvancedDataView(self, writer: ContentHandler):
        """Write the Advanced Data View to the output stream.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
        """
        if writer is None:
            raise TypeError("writer is None")

        writer = XMLStreamWriterHelper(writer)
        ns = FCSDataViewNamespaces.ADV

        FCSRecordXMLStreamWriter.startDataView(writer, ns.mimetype)

        with writer.prefix(ns.prefix, ns.namespace), writer.element(
            "Advanced", ns.namespace, attrs={"unit": self.unit.value}
        ):
            # segments
            with writer.element("Segments", ns.namespace):
                for segment in self.segments:
                    # FIXME: unit translation (long -> time)
                    attrs = {
                        "id": segment.id,
                        "start": str(segment.start),
                        "end": str(segment.end),
                    }
                    if segment.ref:
                        attrs["ref"] = segment.ref
                    writer.startElementNS((ns.namespace, "Segment"), attrs=attrs)
                    writer.endElementNS((ns.namespace, "Segment"))

            # layers
            with writer.element("Layers", ns.namespace):
                for layer_id, layer in self.layers.items():
                    with writer.element("Layer", ns.namespace, attrs={"id": layer_id}):
                        for span in layer:
                            attrs = {"ref": span.segment.id}
                            if span.highlight is not None:
                                attrs["highlight"] = span.highlight
                            if span.altValue is not None:
                                attrs["alt-value"] = span.altValue
                            with writer.element("Span", ns.namespace, attrs=attrs):
                                if span.value and not span.value.isspace():
                                    writer.characters(span.value)

        FCSRecordXMLStreamWriter.endDataView(writer)

    def writeHitsDataView(self, writer: ContentHandler, layer_id: str):
        """Convenience method to write HITS Data View.

        Args:
            writer: the `xml.sax.handler.ContentHandler` to use
            layer_id: the layer id of the layer to be serialized as HITS Data View
        """
        if writer is None:
            raise TypeError("writer is None")
        if layer_id is None:
            raise TypeError("layer_id is None")

        spans = self.layers.get(layer_id, None)
        if not spans:
            raise KeyError(f"layer with id '{layer_id}' does not exist")

        writer = XMLStreamWriterHelper(writer)
        ns = FCSDataViewNamespaces.HITS

        FCSRecordXMLStreamWriter.startDataView(writer, ns.mimetype)

        with writer.prefix(ns.prefix, ns.namespace), writer.element(
            "Result", ns.namespace
        ):
            need_space = False
            for span in spans:
                if need_space:
                    writer.characters(" ")
                    need_space = False

                if span.highlight:
                    with writer.element("Hit", ns.namespace):
                        writer.characters(span.value)
                    need_space = True
                else:
                    writer.characters(span.value)
                    if span.value and not span.value[-1].isspace():
                        need_space = True

        FCSRecordXMLStreamWriter.endDataView(writer)


# ---------------------------------------------------------------------------
