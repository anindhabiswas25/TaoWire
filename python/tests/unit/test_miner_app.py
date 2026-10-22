"""miner/routes.py and miner/app.py: registration rules, uvicorn options, run()."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from tensorwire import Miner as LazyMiner
from tensorwire.errors import ConfigError, StartupError
from tensorwire.miner import app as app_mod
from tensorwire.miner.app import MAX_HEADER_BYTES, Miner
from tensorwire.miner.pipeline import raw_target
from tensorwire.miner.routes import RouteContext, RouteRegistry
from tensorwire.policy.caller import CallerPolicy
from tensorwire.testing.keys import dev_key


class Model(BaseModel):
    x: int


async def handler(req: Any, ctx: RouteContext) -> Model:
    return Model(x=1)


def add(registry: RouteRegistry, path: str = "/v1/a", **kwargs: Any) -> Any:
    args: dict[str, Any] = {
        "timeout_s": 1.0,
        "max_body_bytes": 10,
        "policy": CallerPolicy(),
    }
    args.update(kwargs)
    return registry.add(path, handler, **args)


@pytest.mark.parametrize(
    ("path", "kwargs", "error"),
    [
        ("v1/a", {}, "plain absolute path"),
        ("/v1/a?x=1", {}, "plain absolute path"),
        ("/v1/{id}", {}, "plain absolute path"),
        ("/healthz", {}, "reserved"),
        ("/metrics", {}, "reserved"),
        ("/v1/a", {"method": "PUT"}, "POST or GET"),
        ("/v1/a", {"method": "GET", "request": Model}, "no request model"),
        ("/v1/a", {"timeout_s": 0}, "timeout_s"),
        ("/v1/a", {"timeout_s": float("inf")}, "timeout_s"),
        ("/v1/a", {"max_body_bytes": 0}, "max_body_bytes"),
    ],
)
def test_route_validation(path: str, kwargs: dict[str, Any], error: str) -> None:
    with pytest.raises(ValueError, match=error):
        add(RouteRegistry(), path, **kwargs)


def test_registry_rules() -> None:
    reg = RouteRegistry()
    route = add(reg)
    assert reg.get("/v1/a") is route
    assert reg.get("/v1/b") is None
    assert list(reg) == [route]
    assert len(reg) == 1
    assert route.is_async
    with pytest.raises(ValueError, match="already registered"):
        add(reg)
    with pytest.raises(TypeError, match="callable"):
        reg.add("/v1/b", "nope", timeout_s=1, max_body_bytes=1, policy=CallerPolicy())  # type: ignore[arg-type]
    reg.freeze()
    with pytest.raises(RuntimeError, match=r"before miner\.app is built"):
        add(reg, "/v1/c")


def test_routes_after_app_is_built_are_refused(tw_miner: Miner) -> None:
    _ = tw_miner.app
    with pytest.raises(RuntimeError, match=r"before miner\.app is built"):
        tw_miner.route("/v1/late")(handler)


def test_route_defaults_come_from_settings(tw_miner: Miner) -> None:
    tw_miner.route("/v1/d")(handler)
    route = tw_miner.routes.get("/v1/d")
    assert route is not None
    s = tw_miner.settings
    assert (route.timeout_s, route.max_body_bytes) == (
        s.handler_timeout_s,
        s.max_body_bytes,
    )
    assert route.policy == CallerPolicy.from_settings(s)
    assert route.method == "POST"


def test_app_has_no_public_docs(tw_miner: Miner) -> None:
    app = tw_miner.app
    assert app is tw_miner.app
    assert (app.openapi_url, app.docs_url, app.redoc_url) == (None, None, None)


def test_lazy_public_api() -> None:
    import tensorwire

    assert LazyMiner is Miner
    assert tensorwire.CallerPolicy is CallerPolicy
    with pytest.raises(AttributeError, match="no attribute 'Nope'"):
        _ = tensorwire.Nope


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ({"raw_path": b"/a%20b", "path": "/a b", "query_string": b"q=1"}, "/a%20b?q=1"),
        ({"raw_path": b"/a", "path": "/a", "query_string": b""}, "/a"),
        ({"path": "/a b"}, "/a%20b"),
    ],
)
def test_raw_target(scope: dict[str, Any], expected: str) -> None:
    assert raw_target(scope) == expected


def test_uvicorn_options(tw_miner_kwargs: dict[str, Any], tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("c")
    key.write_text("k")
    settings = tw_miner_kwargs["settings"].model_copy(
        update={"tls_cert_file": cert, "tls_key_file": key, "drain_s": 0.2}
    )
    opts = Miner(**{**tw_miner_kwargs, "settings": settings}).uvicorn_options()
    assert opts["ssl_certfile"] == str(cert)
    assert opts["ssl_keyfile"] == str(key)
    assert opts["timeout_graceful_shutdown"] == 1
    assert opts["h11_max_incomplete_event_size"] == MAX_HEADER_BYTES
    assert opts["timeout_keep_alive"] == 5
    assert opts["proxy_headers"] is False
    assert opts["server_header"] is False


def test_run_exits_with_the_startup_error_code(
    tw_miner: Miner, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refuse(self: Miner) -> None:
        raise StartupError("register first", exit_code=3)

    monkeypatch.setattr(Miner, "_serve", refuse)
    monkeypatch.setattr(app_mod, "configure_logging", lambda level: None)
    with pytest.raises(SystemExit) as info:
        tw_miner.run()
    assert info.value.code == 3


def test_run_with_workers_needs_an_import_path(
    tw_miner_kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = tw_miner_kwargs["settings"].model_copy(
        update={"workers": 2, "unsafe_allow_memory_nonce_multiworker": True}
    )
    miner = Miner(**{**tw_miner_kwargs, "settings": settings})
    monkeypatch.setattr(app_mod, "configure_logging", lambda level: None)
    with pytest.raises(SystemExit) as info:
        miner.run()
    assert info.value.code == 2
    calls: list[tuple[Any, dict[str, Any]]] = []
    monkeypatch.setattr(
        app_mod.uvicorn, "run", lambda app, **kw: calls.append((app, kw))
    )
    miner.run(app_import="my_miner:miner.app")
    assert calls[0][0] == "my_miner:miner.app"
    assert calls[0][1]["workers"] == 2
    assert calls[0][1]["lifespan"] == "on"


async def test_external_server_lifespan_starts_and_stops(tw_miner: Miner) -> None:
    app = tw_miner.app
    async with app.router.lifespan_context(app):
        assert tw_miner.lifecycle.ready
    assert not tw_miner.lifecycle.ready


async def test_lifespan_after_run_start_only_stops(tw_miner: Miner) -> None:
    await tw_miner.lifecycle.start()
    app = tw_miner.app
    async with app.router.lifespan_context(app):
        assert tw_miner.lifecycle.ready
    assert not tw_miner.lifecycle.ready


def test_from_env(tw_env: Any, tmp_path: Path) -> None:
    tw_env.set(netuid=4, wallet_name="m", external_ip="44.1.2.3")
    miner = Miner.from_env(hotkey=dev_key("bob").keypair)
    assert miner.settings.netuid == 4
    with pytest.raises(ConfigError):
        Miner.from_env(tmp_path / "missing.env")
