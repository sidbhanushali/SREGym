import base64
import json

from sregym.conductor.problems.secret_rotation_partial_propagation import (
    SecretRotationPartialPropagationAstronomyShop,
)


def _problem(run_output):
    problem = SecretRotationPartialPropagationAstronomyShop.__new__(SecretRotationPartialPropagationAstronomyShop)
    problem.namespace = "astronomy-shop"
    problem.secret_key = "DB_CONNECTION_STRING"
    problem._run = lambda command, input_data=None: run_output(command)
    return problem


def _deployment_json(env_entry):
    return json.dumps(
        {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "accounting", "env": [env_entry] if env_entry else []},
                        ]
                    }
                }
            }
        }
    )


def _secret_json(value):
    encoded = base64.b64encode(value.encode()).decode()
    return json.dumps({"data": {"DB_CONNECTION_STRING": encoded}})


def test_effective_conn_resolves_literal_value():
    literal = "Host=postgresql;Username=otelu;Password=otelp;Database=otel"
    env_entry = {"name": "DB_CONNECTION_STRING", "value": literal}
    problem = _problem(lambda command: _deployment_json(env_entry))

    assert problem._effective_conn("accounting") == literal


def test_effective_conn_resolves_through_any_secret_reference():
    env_entry = {
        "name": "DB_CONNECTION_STRING",
        "valueFrom": {"secretKeyRef": {"name": "accounting-db", "key": "DB_CONNECTION_STRING"}},
    }
    resolved = "Host=postgresql;Username=otelu;Password=otelp_3v8n5rt2;Database=otel"

    def run(command):
        if "get deployment" in command:
            return _deployment_json(env_entry)
        assert "get secret accounting-db" in command
        return _secret_json(resolved)

    problem = _problem(run)

    assert problem._effective_conn("accounting") == resolved


def test_effective_conn_is_none_when_env_is_absent():
    problem = _problem(lambda command: _deployment_json(None))

    assert problem._effective_conn("accounting") is None


def test_root_cause_names_the_missed_consumer():
    # The judge ground truth must localize to accounting and name the literal
    # env mechanism; guard the strings the rubric depends on.
    problem = SecretRotationPartialPropagationAstronomyShop.__new__(SecretRotationPartialPropagationAstronomyShop)
    text = problem.build_structured_root_cause(
        component="deployment/accounting",
        namespace="astronomy-shop",
        description="x",
    )

    assert text.startswith("[fault_spec] component=deployment/accounting; namespace=astronomy-shop")
