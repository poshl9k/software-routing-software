"""JSON-RPC 2.0 over an injected message-framed, synchronous transport."""
from threading import Lock
from typing import Annotated, Any, Literal, Protocol
from uuid import uuid4

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator
from ..schema import Model

RequestID = StrictInt | StrictStr
VersionID = Annotated[int, Field(strict=True, ge=1)]
Method = Literal["apply_version", "confirm_version", "rollback", "status",
                 "diag_ping", "diag_traceroute", "nft_counters", "list_interfaces",
                 "list_addresses", "update_status", "apply_update",
                 "update_source", "source_status"]


class ApplyParams(Model):
    version_id: VersionID
    safe_mode: StrictBool = False
    confirmation_timeout: int = Field(default=180, strict=True, ge=60, le=600)


class ConfirmParams(Model):
    version_id: VersionID


class EmptyParams(Model):
    pass


class PingParams(Model):
    host: StrictStr
    count: StrictInt = Field(ge=1, le=5)
    source_interface: StrictStr | None = None


class HostParams(Model):
    host: StrictStr


class ApplyUpdateParams(Model):
    # A pinned release commit; validated again against the host manifest before
    # anything runs (never an arbitrary value or a branch).
    release: StrictStr = Field(pattern=r'^[0-9a-f]{40}$')


class UpdateSourceParams(Model):
    """Manual subscription/rule-set update (typed; no shell, no free-form args).

    Only data crosses the RPC: a source name, an https URL, a kind/format and
    the explicit user-source authorization flag plus limits. The agent decides
    allowlisting and SSRF policy; the URL is never passed to a shell.
    """
    name: Annotated[str, Field(strict=True, pattern=r'^[a-zA-Z][a-zA-Z0-9_]{0,30}$')]
    url: StrictStr
    kind: Literal["subscription", "rule_set"] = "rule_set"
    format: Literal["auto", "sing-box", "clash", "v2ray", "base64",
                    "json", "rule-set", "text", "srs"] = "auto"
    # Explicit, separate permission for a user-supplied (non-built-in) source.
    authorized: StrictBool = False
    scheduled: StrictBool = False
    max_bytes: StrictInt = Field(default=5_000_000, ge=1024, le=50_000_000)
    timeout: StrictInt = Field(default=20, ge=1, le=120)


PARAMS = {"apply_version": ApplyParams, "confirm_version": ConfirmParams,
          "rollback": EmptyParams, "status": EmptyParams,
          "diag_ping": PingParams, "diag_traceroute": HostParams,
          "nft_counters": EmptyParams, "list_interfaces": EmptyParams,
          "list_addresses": EmptyParams, "update_status": EmptyParams,
          "apply_update": ApplyUpdateParams,
          "update_source": UpdateSourceParams, "source_status": EmptyParams}


class RPCRequest(Model):
    jsonrpc: Literal["2.0"] = "2.0"
    id: RequestID
    method: Method
    params: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_params(self):
        PARAMS[self.method].model_validate(self.params)
        return self


class RPCError(Model):
    code: StrictInt
    message: StrictStr
    data: Any = None


class RPCResponse(Model):
    jsonrpc: Literal["2.0"] = "2.0"
    id: RequestID | None
    result: Any = None
    error: RPCError | None = None

    @model_validator(mode="after")
    def exactly_one_payload(self):
        fields = self.model_fields_set
        if ("result" in fields) == ("error" in fields):
            raise ValueError("rpc.result_or_error_required")
        if "error" in fields and self.error is None:
            raise ValueError("rpc.invalid_error")
        return self


def build_request(method: Method, params: dict | Model | None = None,
                  request_id: RequestID | None = None) -> RPCRequest:
    if isinstance(params, Model):
        params = params.model_dump(mode="json")
    return RPCRequest(id=uuid4().hex if request_id is None else request_id,
                      method=method, params={} if params is None else params)


def parse_response(payload: str | bytes | dict,
                   expected_id: RequestID | None = None) -> RPCResponse:
    response = (RPCResponse.model_validate(payload) if isinstance(payload, dict)
                else RPCResponse.model_validate_json(payload))
    if expected_id is not None and (type(response.id) is not type(expected_id)
                                    or response.id != expected_id):
        raise ValueError("rpc.id_mismatch")
    return response


class Transport(Protocol):
    """Each send/recv transfers one full JSON message; framing/timeouts belong here."""
    def send(self, message: bytes) -> None: ...
    def recv(self) -> bytes: ...


class AgentRPCError(Exception):
    def __init__(self, error: RPCError):
        super().__init__("agent.rpc_error")
        self.error = error


class AgentClient:
    def __init__(self, transport: Transport):
        self.transport = transport
        self._lock = Lock()

    def call(self, method: Method, params: dict | Model | None = None):
        request = build_request(method, params)
        with self._lock:
            self.transport.send(request.model_dump_json().encode())
            response = parse_response(self.transport.recv(), request.id)
        if response.error is not None:
            raise AgentRPCError(response.error)
        return response.result
