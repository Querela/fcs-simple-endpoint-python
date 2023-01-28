from typing import Dict
from typing import List
from typing import Optional

from clarin.sru.constants import SRUDiagnostics
from clarin.sru.constants import SRUParam
from clarin.sru.constants import SRUVersion
from clarin.sru.diagnostic import SRUDiagnosticList
from clarin.sru.queryparser import SRUQuery
from clarin.sru.queryparser import SRUQueryParser
from fcsql import QueryNode
from fcsql import QueryParser
from fcsql import QueryParserException

from clarin.sru.fcs.constants import FCSQueryType

# ---------------------------------------------------------------------------


class FCSQuery(SRUQuery[QueryNode]):
    @property
    def query_type(self) -> str:
        return FCSQueryType.FCS.value


class FCSQueryParser(SRUQueryParser[QueryNode]):
    """Default query parser to parse FCS-QL."""

    def __init__(self) -> None:
        super().__init__()
        self.parser = QueryParser()

    @property
    def query_type(self) -> str:
        return FCSQueryType.FCS

    @property
    def query_parameter_names(self) -> List[str]:
        return [SRUParam.QUERY.value]

    def supports_version(self, version: Optional[SRUVersion]) -> bool:
        if not version:
            raise TypeError("Argument version is invalid/None.")
        # FCS-QL is only supported by SRU 2.0
        return version >= SRUVersion.VERSION_2_0

    def parse_query(
        self,
        version: SRUVersion,
        parameters: Dict[str, str],
        diagnostics: SRUDiagnosticList,
    ) -> Optional[SRUQuery[QueryNode]]:
        raw_query = parameters.get(SRUParam.QUERY)
        if raw_query is None:
            diagnostics.add_diagnostic(
                SRUDiagnostics.GENERAL_SYSTEM_ERROR,
                message="no query passed to query parser",
            )
            return None

        try:
            parsed_query: QueryNode = self.parser.parse(raw_query)
            return FCSQuery(raw_query, parsed_query)
        except QueryParserException as ex:
            diagnostics.add_diagnostic(
                SRUDiagnostics.QUERY_SYNTAX_ERROR, message=str(ex)
            )
        except Exception:
            diagnostics.add_diagnostic(
                SRUDiagnostics.GENERAL_SYSTEM_ERROR,
                message="Unexpected error while parsing query.",
            )
        return None


# ---------------------------------------------------------------------------
