import io
import logging
import os.path

from clarin.sru.constants import SRURecordXmlEscaping
from clarin.sru.xml.writer import SRUXMLStreamWriter

from clarin.sru.fcs.server.search import SimpleEndpointSearchEngineBase
from clarin.sru.fcs.xml.reader import SimpleEndpointDescriptionParser

if __name__ == "__main__":
    FN = os.path.join(os.path.dirname(__file__), "endpoint-description.xml")

    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger(__name__).info("Load file from %s", FN)

    ep = SimpleEndpointDescriptionParser.parse(FN)

    buf = io.StringIO()
    out = SRUXMLStreamWriter(buf, SRURecordXmlEscaping.STRING, indent=2)
    SimpleEndpointSearchEngineBase._write_EndpointDescription(out, ep)

    # out.endDocument()
    out.xml_output_stream.flush()
    content = buf.getvalue()

    print(content)
