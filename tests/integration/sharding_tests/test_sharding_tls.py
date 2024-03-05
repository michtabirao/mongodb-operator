#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import secrets
import string
import time

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from ..tls_tests import helpers as tls_helpers

# from .writes_helpers import writes_helpers
from ..helpers import get_leader_id, get_password, set_password
from . import writes_helpers

CERTS_APP_NAME = "self-signed-certificates"
SHARD_ONE_APP_NAME = "shard-one"
SHARD_TWO_APP_NAME = "shard-two"
CONFIG_SERVER_APP_NAME = "config-server"
SHARD_COMPONENTS = [SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME, CONFIG_SERVER_APP_NAME]
SHARD_REL_NAME = "sharding"
CONFIG_SERVER_REL_NAME = "config-server"
CERT_REL_NAME = "certificates"
TIMEOUT = 10 * 60


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy a sharded cluster."""
    await deploy_cluster_components(ops_test)

    # deploy the s3 integrator charm
    await ops_test.model.deploy(CERTS_APP_NAME, channel="edge")

    await ops_test.model.wait_for_idle(
        apps=[CERTS_APP_NAME, CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
        raise_on_error=False,
    )


async def test_build_cluster_with_tls(ops_test: OpsTest) -> None:
    """Tests that the cluster can be integrated with TLS"""
    await integrate_cluster(ops_test)
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME],
        idle_period=20,
        timeout=TIMEOUT,
    )

    await integrate_with_tls(ops_test)
    await ops_test.model.wait_for_idle(
        apps=[CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME],
        idle_period=20,
        timeout=TIMEOUT,
    )

    await check_tls_enabled(ops_test)


# TODO test disable

# FUTURE PR - test that shards cannot rotate internal certs


async def check_tls_enabled(ops_test: OpsTest) -> None:
    # check each replica set is running with TLS enabled
    for shard_component in SHARD_COMPONENTS:
        for unit in ops_test.model.applications[shard_component].units:
            await tls_helpers.check_tls(
                ops_test, unit, enable=True, app_name=shard_component, mongos=False
            )

    # check mongos is running with TLS enabled
    for unit in ops_test.model.applications[CONFIG_SERVER_APP_NAME].units:
        await tls_helpers.check_tls(
            ops_test, unit, enable=True, app_name=shard_component, mongos=True
        )


async def deploy_cluster_components(ops_test: OpsTest) -> None:
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(
        my_charm,
        num_units=2,
        config={"role": "config-server"},
        application_name=CONFIG_SERVER_APP_NAME,
    )
    await ops_test.model.deploy(
        my_charm, num_units=2, config={"role": "shard"}, application_name=SHARD_ONE_APP_NAME
    )
    await ops_test.model.deploy(
        my_charm, num_units=1, config={"role": "shard"}, application_name=SHARD_TWO_APP_NAME
    )


async def integrate_cluster(ops_test: OpsTest) -> None:
    """Integrates the cluster components with each other"""
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )
    await ops_test.model.integrate(
        f"{SHARD_TWO_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )


async def integrate_with_tls(ops_test: OpsTest) -> None:
    """Integrates cluster components with self-signed certs operator."""
    await ops_test.model.integrate(
        f"{CERTS_APP_NAME}:{CERT_REL_NAME}",
        f"{CONFIG_SERVER_APP_NAME}:{CERT_REL_NAME}",
    )
    await ops_test.model.integrate(
        f"{CERTS_APP_NAME}:{CERT_REL_NAME}",
        f"{SHARD_ONE_APP_NAME}:{CERT_REL_NAME}",
    )
    await ops_test.model.integrate(
        f"{CERTS_APP_NAME}:{CERT_REL_NAME}",
        f"{SHARD_TWO_APP_NAME}:{CERT_REL_NAME}",
    )
