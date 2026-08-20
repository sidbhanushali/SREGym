import contextlib
import time

from kubernetes import client
from kubernetes.client.rest import ApiException

from sregym.conductor.oracles.base import Oracle


class SecretRotationPartialPropagationMitigation(Oracle):
    """Evaluate whether the credential rotation reached every database client."""

    importance = 1.0
    rollout_timeout_seconds = 120
    probe_timeout_seconds = 60
    poll_interval_seconds = 2
    request_timeout_seconds = 5
    frontend_service = "frontend-proxy"
    product_path = "/api/products"
    expected_product_id = "OLJCESPC7Z"

    def __init__(self, problem):
        """Capture problem constants needed to evaluate mitigation."""
        super().__init__(problem)
        self.old_password = problem.old_password
        self.new_password = problem.new_password
        self.new_conn = problem.new_conn
        self.client_conns = problem.client_conns
        self.baseline_replicas: dict[str, int] = {}

    def capture_baseline(self) -> None:
        """Record healthy pre-fault replica counts for every database client."""
        self.baseline_replicas = {}
        for deployment_name in self.problem.db_client_deployments:
            deployment = self.problem.kubectl.get_deployment(deployment_name, self.problem.namespace)
            replicas = deployment.spec.replicas
            self.baseline_replicas[deployment_name] = 1 if replicas is None else replicas

    # ------------------------------------------------------------------
    # Deployment health helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _desired_replicas(deployment) -> int:
        replicas = deployment.spec.replicas
        return 1 if replicas is None else replicas

    @classmethod
    def _rollout_complete(cls, deployment) -> bool:
        desired = cls._desired_replicas(deployment)
        if desired < 1:
            return False

        generation = deployment.metadata.generation or 0
        status = deployment.status
        return (
            (status.observed_generation or 0) >= generation
            and (status.replicas or 0) == desired
            and (status.updated_replicas or 0) == desired
            and (status.ready_replicas or 0) == desired
            and (status.available_replicas or 0) == desired
            and (status.unavailable_replicas or 0) == 0
        )

    def _wait_for_current_rollout(self, deployment):
        deadline = time.monotonic() + self.rollout_timeout_seconds
        while True:
            if self._rollout_complete(deployment):
                return deployment
            if time.monotonic() >= deadline:
                return None

            time.sleep(self.poll_interval_seconds)
            deployment = self.problem.kubectl.get_deployment(
                deployment.metadata.name,
                self.problem.namespace,
            )

    def _pods_ready(self, deployment_name: str) -> bool:
        """Return whether all current pods of a deployment are Running and Ready."""
        found = False
        for pod in self.problem.kubectl.list_pods(self.problem.namespace).items:
            if deployment_name not in (pod.metadata.name or "") or pod.metadata.deletion_timestamp:
                continue
            found = True
            statuses = pod.status.container_statuses or []
            if pod.status.phase != "Running":
                return False
            if not statuses or not all(status.ready for status in statuses):
                return False
        return found

    def _client_deployments_healthy(self, results: dict) -> bool:
        """Positive + negative structure checks over every database client."""
        for deployment_name in self.problem.db_client_deployments:
            try:
                deployment = self.problem.kubectl.get_deployment(deployment_name, self.problem.namespace)
            except Exception as exc:
                results["reason"] = f"deployment/{deployment_name} does not exist: {exc}"
                return False
            if self._desired_replicas(deployment) < 1:
                results["reason"] = f"deployment/{deployment_name} is scaled to 0"
                return False
            if deployment_name in self.baseline_replicas and (
                self._desired_replicas(deployment) < self.baseline_replicas[deployment_name]
            ):
                results["reason"] = f"deployment/{deployment_name} is scaled below its baseline replica count"
                return False
            if self._wait_for_current_rollout(deployment) is None:
                results["reason"] = f"deployment/{deployment_name} did not complete its current rollout"
                return False
            if not self._pods_ready(deployment_name):
                results["reason"] = f"deployment/{deployment_name} has pods that are not Running and Ready"
                return False
            results["healthy_deployments"].append(deployment_name)
        return True

    # ------------------------------------------------------------------
    # Behavioral probe
    # ------------------------------------------------------------------

    def _run_product_probe(self) -> bool:
        """Prove the catalog path end-to-end from a fresh pod."""
        namespace = self.problem.namespace
        core_v1 = self.problem.kubectl.core_v1_api
        service = core_v1.read_namespaced_service(name=self.frontend_service, namespace=namespace)
        service_ports = service.spec.ports or []
        if not service_ports:
            print(f"[FAIL] Service '{self.frontend_service}' has no ports")
            return False

        port = service_ports[0].port
        url = f"http://{self.frontend_service}.{namespace}.svc.cluster.local:{port}{self.product_path}"
        pod_name = f"rotation-readiness-check-{time.time_ns()}"[:63]
        script = (
            "set -eu; "
            f"wget -q -T {self.request_timeout_seconds} -t 1 -O /tmp/products '{url}'; "
            f"grep -q '{self.expected_product_id}' /tmp/products; "
            "echo PRODUCTS_OK"
        )
        pod = client.V1Pod(
            metadata=client.V1ObjectMeta(
                name=pod_name,
                namespace=namespace,
                labels={"app": "rotation-readiness-check"},
            ),
            spec=client.V1PodSpec(
                restart_policy="Never",
                automount_service_account_token=False,
                containers=[
                    client.V1Container(
                        name="probe",
                        image="busybox:1.36",
                        image_pull_policy="IfNotPresent",
                        command=["sh", "-c", script],
                    )
                ],
            ),
        )

        try:
            core_v1.create_namespaced_pod(namespace=namespace, body=pod)
            deadline = time.monotonic() + self.probe_timeout_seconds
            phase = "Pending"
            while time.monotonic() < deadline:
                current = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
                phase = current.status.phase or "Pending"
                if phase in ("Succeeded", "Failed"):
                    break
                time.sleep(self.poll_interval_seconds)

            logs = core_v1.read_namespaced_pod_log(name=pod_name, namespace=namespace)
            print(logs.strip())
            return phase == "Succeeded" and "PRODUCTS_OK" in logs
        except ApiException as exc:
            print(f"[FAIL] Product catalog probe failed: {exc}")
            return False
        finally:
            with contextlib.suppress(ApiException):
                core_v1.delete_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    grace_period_seconds=0,
                )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, *args, **kwargs) -> dict:
        """Evaluate whether the rotation is complete, consistent, and functional."""
        print("== Secret Rotation Partial Propagation Mitigation Evaluation ==")
        results = {
            "success": False,
            "healthy_deployments": [],
            "secret_conn": None,
            "postgres_accepts_old_password": False,
            "postgres_accepts_new_password": False,
            "postgresql_init_uses_new_password": False,
            "effective_conns": {},
            "product_probe_succeeded": False,
            "reason": "",
        }

        # Structure: every database client exists, at baseline scale, rolled
        # out, with Running+Ready pods. Catches scale-to-0, deletion, and
        # crashlooping "fixes".
        if not self._client_deployments_healthy(results):
            return results

        # The Secret must still hold the required rotated connection string.
        # Catches rolling the Secret back or replacing it with a novel value.
        secret_conn = self.problem._get_secret_conn_string()
        results["secret_conn"] = secret_conn
        if secret_conn != self.new_conn:
            results["reason"] = "the Secret does not contain the required rotated connection string"
            return results

        # Backend truth. Catches rotating PostgreSQL back to the old password
        # instead of completing the rotation.
        results["postgres_accepts_new_password"] = self.problem._postgres_accepts_password(self.new_password)
        results["postgres_accepts_old_password"] = self.problem._postgres_accepts_password(self.old_password)
        results["postgresql_init_uses_new_password"] = self.problem._postgresql_init_uses_password(self.new_password)
        if not results["postgres_accepts_new_password"]:
            results["reason"] = "PostgreSQL does not accept the required rotated password"
            return results
        if results["postgres_accepts_old_password"]:
            results["reason"] = "PostgreSQL still accepts the pre-rotation password"
            return results
        if not results["postgresql_init_uses_new_password"]:
            results["reason"] = "postgresql-init does not declare the required rotated password"
            return results

        # Every client's EFFECTIVE credential (literal or resolved through any
        # Secret reference) must equal its rotated value. Catches the missed
        # consumer being left on the old value, novel credentials pointed at
        # agent-created database users, and fixes that break other clients.
        expected_conns = {deployment: conn_pair[1] for deployment, conn_pair in self.client_conns.items()}
        expected_conns[self.problem.secret_consumer] = self.new_conn
        for deployment_name, expected in expected_conns.items():
            effective = self.problem._effective_conn(deployment_name)
            results["effective_conns"][deployment_name] = effective
            if effective != expected:
                results["reason"] = (
                    f"deployment/{deployment_name} is not configured with its required rotated connection string"
                )
                return results

        # Behavioral: a fresh request through the frontend must return catalog
        # data, proving the Secret-backed client actually serves.
        results["product_probe_succeeded"] = self._run_product_probe()
        if not results["product_probe_succeeded"]:
            results["reason"] = "a fresh /api/products request did not return catalog data"
            return results

        results["success"] = True
        results["reason"] = "credential rotation reached every database client and the application is healthy"
        print("Mitigation Result: Pass")
        return results
