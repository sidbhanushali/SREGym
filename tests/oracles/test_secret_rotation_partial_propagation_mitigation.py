from types import SimpleNamespace

import pytest

from sregym.conductor.oracles.secret_rotation_partial_propagation_mitigation import (
    SecretRotationPartialPropagationMitigation,
)

OLD_PW = "otelp"
NEW_PW = "otelp_3v8n5rt2"
NEW_URI = f"postgres://otelu:{NEW_PW}@postgresql/otel?sslmode=disable"
OLD_URI = f"postgres://otelu:{OLD_PW}@postgresql/otel?sslmode=disable"
CLIENT_CONNS = {
    "accounting": (
        f"Host=postgresql;Username=otelu;Password={OLD_PW};Database=otel",
        f"Host=postgresql;Username=otelu;Password={NEW_PW};Database=otel",
    ),
    "product-reviews": (
        f"host=postgresql user=otelu password={OLD_PW} dbname=otel",
        f"host=postgresql user=otelu password={NEW_PW} dbname=otel",
    ),
}
NOVEL_CONN = "Host=postgresql;Username=shadow;Password=hunter2;Database=otel"
CLIENTS = ["accounting", "product-reviews", "product-catalog"]


def _deployment(name, *, replicas=1, ready=None):
    ready = replicas if ready is None else ready
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, generation=1),
        spec=SimpleNamespace(replicas=replicas),
        status=SimpleNamespace(
            observed_generation=1,
            replicas=replicas,
            updated_replicas=replicas,
            ready_replicas=ready,
            available_replicas=ready,
            unavailable_replicas=replicas - ready,
        ),
    )


def _pod(name, phase="Running", ready=True):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, deletion_timestamp=None),
        status=SimpleNamespace(
            phase=phase,
            container_statuses=[SimpleNamespace(ready=ready)],
        ),
    )


class _CoreV1:
    def __init__(self, *, probe_phase="Succeeded", probe_logs="PRODUCTS_OK\n"):
        self.probe_phase = probe_phase
        self.probe_logs = probe_logs
        self.created_pods = []
        self.deleted_pods = []

    def read_namespaced_service(self, name, namespace):
        return SimpleNamespace(spec=SimpleNamespace(ports=[SimpleNamespace(port=8080)]))

    def create_namespaced_pod(self, namespace, body):
        self.created_pods.append((namespace, body))

    def read_namespaced_pod(self, name, namespace):
        return SimpleNamespace(status=SimpleNamespace(phase=self.probe_phase))

    def read_namespaced_pod_log(self, name, namespace):
        return self.probe_logs

    def delete_namespaced_pod(self, name, namespace, grace_period_seconds):
        self.deleted_pods.append((name, namespace, grace_period_seconds))


class _KubeCtl:
    def __init__(self, *, deployments=None, pods=None, core_v1=None):
        self.deployments = deployments if deployments is not None else {name: _deployment(name) for name in CLIENTS}
        self.pods = pods if pods is not None else [_pod(f"{name}-abc") for name in CLIENTS]
        self.core_v1_api = core_v1 or _CoreV1()

    def get_deployment(self, name, namespace):
        if name not in self.deployments:
            raise RuntimeError(f"deployment {name} not found")
        return self.deployments[name]

    def list_pods(self, namespace):
        return SimpleNamespace(items=self.pods)


def _oracle(
    kubectl=None,
    *,
    secret_conn=NEW_URI,
    accepted_passwords=None,
    init_uses_new=True,
    effective_conns=None,
):
    kubectl = kubectl or _KubeCtl()
    resolved = {
        "accounting": CLIENT_CONNS["accounting"][1],
        "product-reviews": CLIENT_CONNS["product-reviews"][1],
        "product-catalog": NEW_URI,
    }
    if effective_conns:
        resolved.update(effective_conns)
    accepted = {NEW_PW} if accepted_passwords is None else accepted_passwords
    problem = SimpleNamespace(
        namespace="astronomy-shop",
        faulty_service="accounting",
        secret_consumer="product-catalog",
        db_client_deployments=list(CLIENTS),
        old_password=OLD_PW,
        new_password=NEW_PW,
        new_conn=NEW_URI,
        client_conns=CLIENT_CONNS,
        kubectl=kubectl,
        _get_secret_conn_string=lambda: secret_conn,
        _postgres_accepts_password=lambda password: password in accepted,
        _postgresql_init_uses_password=lambda password: init_uses_new,
        _effective_conn=lambda deployment: resolved.get(deployment),
    )
    oracle = SecretRotationPartialPropagationMitigation(problem)
    oracle.baseline_replicas = {name: 1 for name in CLIENTS}
    oracle.rollout_timeout_seconds = 0
    oracle.poll_interval_seconds = 0
    return oracle


def test_accepts_completed_rotation_with_literal_new_value():
    core_v1 = _CoreV1()
    result = _oracle(_KubeCtl(core_v1=core_v1)).evaluate()

    assert result["success"] is True
    assert result["product_probe_succeeded"] is True
    assert sorted(result["healthy_deployments"]) == sorted(CLIENTS)
    assert len(core_v1.created_pods) == 1
    assert len(core_v1.deleted_pods) == 1


def test_accepts_accounting_migrated_to_a_properly_formatted_secret():
    # _effective_conn resolves secretKeyRefs, so a Secret-backed fix looks the
    # same as a literal one as long as the resolved value is the rotated conn.
    result = _oracle(effective_conns={"accounting": CLIENT_CONNS["accounting"][1]}).evaluate()

    assert result["success"] is True


def test_rejects_missed_consumer_still_on_old_credential():
    result = _oracle(effective_conns={"accounting": CLIENT_CONNS["accounting"][0]}).evaluate()

    assert result["success"] is False
    assert "deployment/accounting" in result["reason"]


def test_cheat_rotate_postgres_back_to_old_password():
    result = _oracle(accepted_passwords={OLD_PW, NEW_PW}).evaluate()

    assert result["success"] is False
    assert "pre-rotation password" in result["reason"]


@pytest.mark.parametrize("conn", [OLD_URI, "postgres://otelu:hunter2@postgresql/otel?sslmode=disable"])
def test_cheat_roll_back_or_replace_the_secret(conn):
    core_v1 = _CoreV1()
    result = _oracle(_KubeCtl(core_v1=core_v1), secret_conn=conn).evaluate()

    assert result["success"] is False
    assert "Secret does not contain" in result["reason"]
    assert core_v1.created_pods == []


def test_cheat_scale_the_broken_consumer_to_zero():
    deployments = {name: _deployment(name) for name in CLIENTS}
    deployments["accounting"] = _deployment("accounting", replicas=0, ready=0)
    core_v1 = _CoreV1()
    kubectl = _KubeCtl(deployments=deployments, core_v1=core_v1)

    result = _oracle(kubectl).evaluate()

    assert result["success"] is False
    assert "scaled to 0" in result["reason"]
    assert core_v1.created_pods == []


def test_cheat_point_accounting_at_a_novel_database_user():
    result = _oracle(effective_conns={"accounting": NOVEL_CONN}).evaluate()

    assert result["success"] is False
    assert "deployment/accounting" in result["reason"]


def test_cheat_fix_accounting_by_reverting_another_client():
    result = _oracle(effective_conns={"product-reviews": CLIENT_CONNS["product-reviews"][0]}).evaluate()

    assert result["success"] is False
    assert "deployment/product-reviews" in result["reason"]


def test_rejects_stale_init_configmap_that_a_restart_would_undo():
    result = _oracle(init_uses_new=False).evaluate()

    assert result["success"] is False
    assert "postgresql-init" in result["reason"]


def test_rejects_crashlooping_pods_even_when_deployment_reports_desired():
    pods = [_pod(f"{name}-abc") for name in ("product-reviews", "product-catalog")]
    pods.append(_pod("accounting-abc", phase="Running", ready=False))
    result = _oracle(_KubeCtl(pods=pods)).evaluate()

    assert result["success"] is False
    assert "Running and Ready" in result["reason"]


def test_rejects_failed_product_probe():
    core_v1 = _CoreV1(probe_phase="Failed", probe_logs="")
    result = _oracle(_KubeCtl(core_v1=core_v1)).evaluate()

    assert result["success"] is False
    assert "/api/products" in result["reason"]
    assert len(core_v1.deleted_pods) == 1
