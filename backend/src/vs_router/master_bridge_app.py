"""Externally reachable subset of the node's local bridge API.

Use a separate Unix socket; even a proxy path-matching mistake cannot expose
local portal endpoints through this process.
"""
from .internal_app import create_internal_app


def create_master_bridge_app(**kwargs):
    app = create_internal_app(**kwargs)
    app.router.routes[:] = [route for route in app.router.routes
                            if getattr(route, 'path', '').startswith('/internal/master/')]
    return app


app = create_master_bridge_app()
