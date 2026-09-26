import json
import pytest
from pydantic import ValidationError
from vs_router.agent.rpc import AgentClient, AgentRPCError, build_request, parse_response
from vs_router.api.configuration import structural_diff


@pytest.mark.parametrize("method,params", [
    ("apply_version", {"version_id": 1}), ("confirm_version", {"version_id": 2}),
    ("rollback", {}), ("status", {}),
])
def test_request_whitelist(method, params):
    request = build_request(method, params, request_id=1)
    assert request.model_dump() == {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


@pytest.mark.parametrize("method,params", [
    ("shell", {}), ("apply_version", {}), ("confirm_version", {"version_id": True}),
    ("apply_version", {"version_id": 0}), ("apply_version", {"version_id": 1, "confirmation_timeout": 59}),
    ("status", {"command": "ls"}), ("rollback", {"version_id": 1}),
])
def test_invalid_requests(method, params):
    with pytest.raises(ValidationError):
        build_request(method, params)


@pytest.mark.parametrize("payload", [
    {"jsonrpc": "1.0", "id": 1, "result": {}}, {"jsonrpc": "2.0", "id": 1},
    {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1, "message": "bad"}},
    {"jsonrpc": "2.0", "id": 1, "error": None}, {"jsonrpc": "2.0", "id": True, "result": {}},
    {"jsonrpc": "2.0", "id": 1, "error": {"code": "-1", "message": "bad"}},
])
def test_invalid_responses(payload):
    with pytest.raises(ValidationError):
        parse_response(json.dumps(payload))


def test_response_ids_and_null_result():
    assert parse_response('{"jsonrpc":"2.0","id":1,"result":null}', 1).result is None
    with pytest.raises(ValueError, match="id_mismatch"):
        parse_response({"jsonrpc": "2.0", "id": "1", "result": {}}, 1)
    with pytest.raises(ValidationError):
        parse_response("not json")


class FakeTransport:
    def __init__(self, error=False):
        self.error = error
        self.sent = []

    def send(self, message):
        self.sent.append(json.loads(message))

    def recv(self):
        payload = {"jsonrpc": "2.0", "id": self.sent[-1]["id"]}
        payload.update({"error": {"code": -32000, "message": "failed"}} if self.error
                       else {"result": {"status": "idle"}})
        return json.dumps(payload).encode()


def test_client_transport_success_error_and_no_send_on_invalid():
    transport = FakeTransport()
    client = AgentClient(transport)
    assert client.call("status") == {"status": "idle"}
    with pytest.raises(ValidationError):
        client.call("shell")
    assert len(transport.sent) == 1
    transport.error = True
    with pytest.raises(AgentRPCError) as exc:
        client.call("rollback")
    assert exc.value.error.code == -32000


def test_json_pointer_diff():
    assert structural_diff({"a/b~": [1, 2]}, {"a/b~": [3]}) == [
        {"op": "replace", "path": "/a~1b~0/0", "before": 1, "after": 3},
        {"op": "remove", "path": "/a~1b~0/1", "before": 2}]
    assert structural_diff({}, {"a": None}) == [{"op": "add", "path": "/a", "after": None}]
    assert structural_diff(True, 1)[0]["op"] == "replace"
    assert structural_diff({"v": True}, {"v": 1})[0]["path"] == "/v"
