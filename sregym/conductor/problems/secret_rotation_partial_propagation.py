"""Secret rotation partial propagation problem for Astronomy Shop.

Real-world story
----------------
A database credential rotation completes at the source but propagation is
partial: consumers that read the credential from the shared Secret pick up the
new value, while one consumer that carries the credential as a literal env
value in its Deployment spec is missed. Once existing database sessions are
terminated, the missed consumer fails authentication on every reconnect. The
same class of failure took down Azure AD on 2021-03-15 (a signing key removed
while consumers still depended on it) and appears in Cloudflare's 2025-03-21
credential-rotation incident.

SREGym simulation
-----------------
1. inject_fault: rotate the PostgreSQL password and the Secret, migrate
   product-catalog to read from the Secret, update product-reviews' literal
   value, but leave accounting's literal DB_CONNECTION_STRING at the
   pre-rotation password; then terminate existing database sessions.
2. recover_fault: point accounting at the rotated credential and restart it,
   leaving the whole application consistent on the new credential.

This is the spec-level dual of secret_rotation_stale_env_credentials: there,
the spec is correct and the running pod is stale, so a restart fixes it; here,
every pod faithfully reflects its spec and a restart cannot fix it.

Valid agent mitigations (all accepted by the oracle)
- Set accounting's literal DB_CONNECTION_STRING to the rotated value.
- Point accounting at any Secret whose referenced key holds the rotated value.
"""

import base64
import json
import logging
import shlex
import time

from sregym.conductor.oracles.llm_as_a_judge.llm_as_a_judge_oracle import LLMAsAJudgeOracle
from sregym.conductor.oracles.secret_rotation_partial_propagation_mitigation import (
    SecretRotationPartialPropagationMitigation,
)
from sregym.conductor.problems.base import Problem
from sregym.service.apps.astronomy_shop import AstronomyShop
from sregym.service.kubectl import KubeCtl
from sregym.utils.decorators import mark_fault_injected

logger = logging.getLogger(__name__)


class SecretRotationPartialPropagationAstronomyShop(Problem):
    """Rotate database credentials everywhere except one literal-env consumer."""

    _POSTGRES_ROTATION_ATTEMPTS = 3
    _POSTGRES_PASSWORD_CHECK_ATTEMPTS = 3
    _POSTGRES_PASSWORD_CHECK_INTERVAL_SECONDS = 3
    _VERIFY_TIMEOUT_SECONDS = 60

    def __init__(self):
        """Configure the fixed Astronomy Shop partial-rotation problem."""
        self.app = AstronomyShop()
        self.namespace = self.app.namespace
        super().__init__(app=self.app, namespace=self.namespace)
        self.kubectl = KubeCtl()

        self.faulty_service = "accounting"
        self.backend_service = "postgresql"
        self.secret_name = "product-catalog-db-conn"
        self.secret_key = "DB_CONNECTION_STRING"
        self.secret_consumer = "product-catalog"
        self.postgresql_init_configmap = "postgresql-init"
        self.postgresql_init_key = "init.sql"
        self.db_user = "otelu"
        self.db_name = "otel"
        self.old_password = "otelp"
        self.new_password = "otelp_3v8n5rt2"
        # Each client consumes the credential in its own format; the rotation
        # must land in every one of them.
        self.old_conn = f"postgres://{self.db_user}:{self.old_password}@postgresql/otel?sslmode=disable"
        self.new_conn = f"postgres://{self.db_user}:{self.new_password}@postgresql/otel?sslmode=disable"
        self.client_conns = {
            "accounting": (
                f"Host=postgresql;Username={self.db_user};Password={self.old_password};Database={self.db_name}",
                f"Host=postgresql;Username={self.db_user};Password={self.new_password};Database={self.db_name}",
            ),
            "product-reviews": (
                f"host=postgresql user={self.db_user} password={self.old_password} dbname={self.db_name}",
                f"host=postgresql user={self.db_user} password={self.new_password} dbname={self.db_name}",
            ),
        }
        self.db_client_deployments = ["accounting", "product-reviews", "product-catalog"]

        self.root_cause = self.build_structured_root_cause(
            component=f"deployment/{self.faulty_service}",
            namespace=self.namespace,
            description=(
                "PostgreSQL credentials were rotated and the rotation reached the Kubernetes Secret and the other "
                "database clients, but deployment/accounting still carries the pre-rotation password as a literal "
                "DB_CONNECTION_STRING value in its pod template. After existing database sessions were terminated, "
                "accounting fails PostgreSQL authentication on every reconnect and stops processing work. Restarting "
                "the pod cannot fix it because the stale credential lives in the Deployment spec; the mitigation is "
                "updating accounting's configured credential to the rotated value."
            ),
        )

        self.diagnosis_oracle = LLMAsAJudgeOracle(problem=self, expected=self.root_cause)
        self.app.create_workload()
        self.mitigation_oracle = SecretRotationPartialPropagationMitigation(problem=self)

    # ------------------------------------------------------------------
    # kubectl helpers
    # ------------------------------------------------------------------

    def _run(self, command: str, input_data: str | None = None) -> str:
        """Run a kubectl command through the repository wrapper."""
        logger.debug("[secret-rotation-partial] %s", command)
        return self.kubectl.exec_command(command, input_data=input_data)

    def _apply_secret(self, conn_string: str) -> None:
        """Create or update the DB connection Secret with the given connection string."""
        literal = shlex.quote(f"{self.secret_key}={conn_string}")
        manifest = self._run(
            f"kubectl create secret generic {self.secret_name} -n {self.namespace} "
            f"--from-literal={literal} --dry-run=client -o yaml"
        )
        self._run("kubectl apply -f -", input_data=manifest)

    def _set_literal_env(self, deployment: str, conn_string: str) -> None:
        """Set a deployment's DB_CONNECTION_STRING to a literal value."""
        output = self._run(
            f"kubectl set env deployment/{deployment} -n {self.namespace} "
            f"--containers={deployment} {self.secret_key}={shlex.quote(conn_string)}"
        )
        if "error" in output.lower() or "invalid" in output.lower():
            raise RuntimeError(f"Failed to set literal {self.secret_key} for {deployment}: {output}")

    def _set_secret_env(self, deployment: str) -> None:
        """Make a deployment read DB_CONNECTION_STRING from the Secret."""
        output = self._run(
            f"kubectl set env deployment/{deployment} -n {self.namespace} "
            f"--containers={deployment} --from=secret/{self.secret_name} --keys={self.secret_key}"
        )
        if "error" in output.lower() or "invalid" in output.lower():
            raise RuntimeError(f"Failed to set {self.secret_key} from Secret for {deployment}: {output}")

    def _rollout_restart(self, deployment: str, timeout: str = "180s") -> None:
        """Restart a Deployment and wait for its rollout to finish."""
        self._run(f"kubectl rollout restart deployment/{deployment} -n {self.namespace}")
        self._run(f"kubectl rollout status deployment/{deployment} -n {self.namespace} --timeout={timeout}")

    def _wait_rollout(self, deployment: str, timeout: str = "180s") -> None:
        """Wait for a Deployment's current rollout to finish."""
        self._run(f"kubectl rollout status deployment/{deployment} -n {self.namespace} --timeout={timeout}")

    # ------------------------------------------------------------------
    # PostgreSQL helpers
    # ------------------------------------------------------------------

    def _postgres_exec(self, password: str, sql_or_query: str, tuples_only: bool = False) -> str:
        """Run a psql command against PostgreSQL using the specified password."""
        psql_args = "-tAc" if tuples_only else "-c"
        script = (
            f"PGPASSWORD={shlex.quote(password)} psql -h {shlex.quote(self.backend_service)} "
            f"-U {shlex.quote(self.db_user)} -d {shlex.quote(self.db_name)} "
            f"{psql_args} {shlex.quote(sql_or_query)}"
        )
        return self._run(
            f"kubectl exec -n {self.namespace} deploy/{self.backend_service} -- sh -lc {shlex.quote(script)}"
        )

    def _rotate_postgres_password(self, from_password: str, to_password: str) -> None:
        """Rotate the PostgreSQL password for the application user."""
        last_output = ""
        for attempt in range(self._POSTGRES_ROTATION_ATTEMPTS):
            last_output = self._postgres_exec(
                from_password,
                f"ALTER USER {self.db_user} WITH PASSWORD '{to_password}';",
            )
            if "ALTER ROLE" in last_output or self._postgres_accepts_password(to_password):
                return
            if attempt < self._POSTGRES_ROTATION_ATTEMPTS - 1:
                time.sleep(self._POSTGRES_PASSWORD_CHECK_INTERVAL_SECONDS)
        raise RuntimeError(f"Failed to rotate PostgreSQL password for {self.db_user}: {last_output}")

    def _drop_postgres_connections(self, password: str) -> None:
        """Terminate existing app DB sessions so clients must re-authenticate."""
        output = self._postgres_exec(
            password,
            f"select pg_terminate_backend(pid) from pg_stat_activity "
            f"where usename = '{self.db_user}' and pid <> pg_backend_pid();",
            tuples_only=True,
        )
        if "FATAL" in output or "ERROR" in output:
            raise RuntimeError(f"Failed to terminate existing PostgreSQL sessions: {output}")

    def _postgres_accepts_password(self, password: str) -> bool:
        """Return whether PostgreSQL accepts the given password for the app user."""
        script = (
            f"if PGPASSWORD={shlex.quote(password)} psql -h {shlex.quote(self.backend_service)} "
            f"-U {shlex.quote(self.db_user)} -d {shlex.quote(self.db_name)} -tAc 'select 1' >/dev/null 2>&1; "
            "then echo 1; else echo 0; fi"
        )
        command = f"kubectl exec -n {self.namespace} deploy/{self.backend_service} -- sh -lc {shlex.quote(script)}"
        for attempt in range(self._POSTGRES_PASSWORD_CHECK_ATTEMPTS):
            output = self._run(command)
            if output.strip() == "1":
                return True
            if attempt < self._POSTGRES_PASSWORD_CHECK_ATTEMPTS - 1:
                time.sleep(self._POSTGRES_PASSWORD_CHECK_INTERVAL_SECONDS)
        return False

    def _get_postgresql_init_sql(self) -> str | None:
        """Return the live PostgreSQL init from the postgresql-init ConfigMap."""
        output = self._run(
            f"kubectl get configmap {self.postgresql_init_configmap} -n {self.namespace} "
            "-o jsonpath='{.data.init\\.sql}'"
        )
        if "not found" in output.lower() or "error from server" in output.lower():
            return None
        return output or None

    def _postgresql_init_uses_password(self, password: str) -> bool:
        """Return whether postgresql-init would recreate the app user with the given password."""
        init_sql = self._get_postgresql_init_sql() or ""
        expected_line = f"CREATE USER {self.db_user} WITH PASSWORD '{password}';"
        other_passwords = (item for item in (self.old_password, self.new_password) if item != password)
        return expected_line in init_sql and not any(
            f"CREATE USER {self.db_user} WITH PASSWORD '{other_password}';" in init_sql
            for other_password in other_passwords
        )

    def _patch_postgresql_init_password(self, password: str) -> None:
        """Update live postgresql-init bootstrap SQL to declare the given password."""
        init_sql = self._get_postgresql_init_sql()
        if not init_sql:
            raise RuntimeError(
                f"ConfigMap {self.postgresql_init_configmap}/{self.postgresql_init_key} is missing or empty."
            )

        from_line = f"CREATE USER {self.db_user} WITH PASSWORD '{self.old_password}';"
        to_line = f"CREATE USER {self.db_user} WITH PASSWORD '{self.new_password}';"
        if password == self.old_password:
            from_line, to_line = to_line, from_line
        if from_line not in init_sql:
            if to_line in init_sql:
                return
            raise RuntimeError(f"Could not find {self.db_user} password declaration in {self.postgresql_init_key}.")

        updated_sql = init_sql.replace(from_line, to_line)
        patch = json.dumps({"data": {self.postgresql_init_key: updated_sql}})
        output = self._run(
            f"kubectl patch configmap {self.postgresql_init_configmap} -n {self.namespace} "
            f"--type=merge -p {shlex.quote(patch)}"
        )
        if "error" in output.lower() or "invalid" in output.lower():
            raise RuntimeError(f"Failed to patch {self.postgresql_init_configmap}: {output}")

    # ------------------------------------------------------------------
    # State inspection helpers (shared with the oracle)
    # ------------------------------------------------------------------

    def _get_secret_conn_string(self) -> str | None:
        """Decode DB_CONNECTION_STRING from the Kubernetes Secret."""
        return self._read_secret_value(self.secret_name, self.secret_key)

    def _read_secret_value(self, secret_name: str, key: str) -> str | None:
        """Decode one key from a named Secret, or None if absent."""
        output = self._run(f"kubectl get secret {secret_name} -n {self.namespace} -o json")
        if "not found" in output.lower() or "error from server" in output.lower():
            return None
        secret = json.loads(output)
        encoded = secret.get("data", {}).get(key)
        if not encoded:
            return None
        return base64.b64decode(encoded).decode("utf-8").strip()

    def _get_deployment_env_entry(self, deployment: str) -> dict | None:
        """Return the DB_CONNECTION_STRING env entry from a Deployment's pod template."""
        output = self._run(f"kubectl get deployment {deployment} -n {self.namespace} -o json")
        try:
            spec = json.loads(output)
        except json.JSONDecodeError:
            return None
        containers = spec.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        container = next((item for item in containers if item.get("name") == deployment), None)
        if container is None and containers:
            container = containers[0]
        for env in (container or {}).get("env", []):
            if env.get("name") == self.secret_key:
                return env
        return None

    def _effective_conn(self, deployment: str) -> str | None:
        """Resolve a Deployment's configured DB connection string (literal or Secret-backed)."""
        env = self._get_deployment_env_entry(deployment)
        if env is None:
            return None
        if "value" in env:
            return env["value"]
        secret_ref = env.get("valueFrom", {}).get("secretKeyRef", {})
        if secret_ref.get("name") and secret_ref.get("key"):
            return self._read_secret_value(secret_ref["name"], secret_ref["key"])
        return None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _recover_to_baseline(self) -> None:
        """Restore pre-rotation state: old password everywhere, no Secret."""
        logger.info("[secret-rotation-partial] Recovering to pre-rotation baseline.")
        if not self._postgres_accepts_password(self.old_password):
            self._rotate_postgres_password(self.new_password, self.old_password)
            if not self._postgres_accepts_password(self.old_password):
                raise RuntimeError("PostgreSQL password restore did not make the baseline password valid.")
        self._patch_postgresql_init_password(self.old_password)
        for deployment, conn_pair in self.client_conns.items():
            self._set_literal_env(deployment, conn_pair[0])
            self._wait_rollout(deployment)
        self._set_literal_env(self.secret_consumer, self.old_conn)
        self._wait_rollout(self.secret_consumer)
        self._run(f"kubectl delete secret {self.secret_name} -n {self.namespace} --ignore-not-found")

    @mark_fault_injected
    def inject_fault(self):
        """Rotate the credential everywhere except accounting, then drop DB sessions."""
        print("== Fault Injection ==")
        self._recover_to_baseline()

        logger.info("[secret-rotation-partial] Creating the Secret with the rotated connection string.")
        self._apply_secret(self.new_conn)

        logger.info("[secret-rotation-partial] Rotating the PostgreSQL backend password.")
        self._rotate_postgres_password(self.old_password, self.new_password)
        self._patch_postgresql_init_password(self.new_password)

        logger.info("[secret-rotation-partial] Migrating product-catalog to the Secret-backed credential.")
        self._set_secret_env(self.secret_consumer)
        self._rollout_restart(self.secret_consumer)

        logger.info("[secret-rotation-partial] Updating product-reviews' literal credential to the rotated value.")
        self._set_literal_env("product-reviews", self.client_conns["product-reviews"][1])
        self._wait_rollout("product-reviews")

        # accounting is deliberately untouched: its literal env keeps the
        # pre-rotation password, exactly like a consumer missed by a runbook.

        logger.info("[secret-rotation-partial] Terminating existing PostgreSQL sessions.")
        self._drop_postgres_connections(self.new_password)

        deadline = time.monotonic() + self._VERIFY_TIMEOUT_SECONDS
        while True:
            env_entry = self._get_deployment_env_entry(self.secret_consumer) or {}
            secret_ref = env_entry.get("valueFrom", {}).get("secretKeyRef", {})
            state = {
                "secret_is_new": self._get_secret_conn_string() == self.new_conn,
                "postgres_new_password": self._postgres_accepts_password(self.new_password),
                "postgres_old_password_rejected": not self._postgres_accepts_password(self.old_password),
                "postgresql_init_is_new": self._postgresql_init_uses_password(self.new_password),
                "product_catalog_reads_secret": secret_ref.get("name") == self.secret_name,
                "product_reviews_is_new": self._effective_conn("product-reviews")
                == self.client_conns["product-reviews"][1],
                "accounting_is_old": self._effective_conn(self.faulty_service)
                == self.client_conns[self.faulty_service][0],
            }
            if all(state.values()):
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(self._POSTGRES_PASSWORD_CHECK_INTERVAL_SECONDS)
        logger.info("[secret-rotation-partial] Verification: %s", state)
        if not all(state.values()):
            raise RuntimeError(f"Fault verification failed; partial-rotation state was not created: {state}")

        print(f"Service: {self.faulty_service} | Namespace: {self.namespace}\n")

    @mark_fault_injected
    def recover_fault(self):
        """Complete the rotation: point accounting at the rotated credential."""
        print("== Fault Recovery ==")
        if not self._postgres_accepts_password(self.new_password):
            self._rotate_postgres_password(self.old_password, self.new_password)

        self._apply_secret(self.new_conn)
        self._patch_postgresql_init_password(self.new_password)
        self._set_literal_env(self.faulty_service, self.client_conns[self.faulty_service][1])
        self._rollout_restart(self.faulty_service)

        print(f"Service: {self.faulty_service} | Namespace: {self.namespace}\n")
