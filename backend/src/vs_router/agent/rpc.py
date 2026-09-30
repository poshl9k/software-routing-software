"""JSON-RPC 2.0 over an injected message-framed, synchronous transport."""
from threading import Lock
from typing import Annotated, Any, Literal, Protocol
from uuid import uuid4

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator
from ..schema import Model

RequestID = StrictInt | StrictStr
VersionID = Annotated[int, Field(strict=True, ge=1)]
Method = Literal["apply_version", "confirm_version", "rollback", "status",
                 "diag_ping", "diag_traceroute", "nft_counters", "list_interfaces"]


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


PARAMS = {"apply_version": ApplyParams, "confirm_version": ConfirmParams,
          "rollback": EmptyParams, "status": EmptyParams,
          "diag_ping": PingParams, "diag_traceroute": HostParams,
          "nft_counters": EmptyParams, "list_interfaces": EmptyParams}


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
