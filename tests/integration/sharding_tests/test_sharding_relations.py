#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import time

import pytest
from juju.errors import JujuAPIError
from pytest_operator.plugin import OpsTest

SHARD_ONE_APP_NAME = "shard"
CONFIG_SERVER_ONE_APP_NAME = "config-server-one"
CONFIG_SERVER_TWO_APP_NAME = "config-server-two"
REPLICATION_APP_NAME = "replication"
APP_CHARM_NAME = "application"
LEGACY_APP_CHARM_NAME = "legacy-application"
MONGOS_APP_NAME = "mongos"
MONGOS_HOST_APP_NAME = "application-host"

SHARDING_COMPONENTS = [SHARD_ONE_APP_NAME, CONFIG_SERVER_ONE_APP_NAME]

CONFIG_SERVER_REL_NAME = "config-server"
SHARD_REL_NAME = "sharding"
DATABASE_REL_NAME = "first-database"
S3_REL_NAME = "s3-credentials"
LEGACY_RELATION_NAME = "obsolete"
S3_APP_NAME = "s3-integrator"
RELATION_LIMIT_MESSAGE = 'cannot add relation "shard:sharding config-server-two:config-server": establishing a new relation for shard:sharding would exceed its maximum relation limit of 1'
# for now we have a large timeout due to the slow drainage of the `config.system.sessions`
# collection. More info here:
# https://stackoverflow.com/questions/77364840/mongodb-slow-chunk-migration-for-collection-config-system-sessions-with-remov
TIMEOUT = 30 * 60


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    application_charm,
    legacy_charm,
    database_charm,
    mongos_host_application_charm,
) -> None:
    """Build and deploy a sharded cluster."""
    await ops_test.model.deploy(
        database_charm,
        config={"role": "config-server"},
        application_name=CONFIG_SERVER_ONE_APP_NAME,
    )
    await ops_test.model.deploy(
        database_charm,
        config={"role": "config-server"},
        application_name=CONFIG_SERVER_TWO_APP_NAME,
    )
    await ops_test.model.deploy(
        database_charm, config={"role": "shard"}, application_name=SHARD_ONE_APP_NAME
    )
    await ops_test.model.deploy(
        MONGOS_APP_NAME,
        channel="6/edge",
        revision=3,
    )
    await ops_test.model.deploy(S3_APP_NAME, channel="edge")

    # TODO: Future PR, once data integrator works with mongos charm deploy that charm instead of
    # packing and deploying the charm in the application dir.
    await ops_test.model.deploy(
        mongos_host_application_charm, application_name=MONGOS_HOST_APP_NAME
    )

    await ops_test.model.deploy(database_charm, application_name=REPLICATION_APP_NAME)
    await ops_test.model.deploy(application_charm, application_name=APP_CHARM_NAME)
    await ops_test.model.deploy(legacy_charm, application_name=LEGACY_APP_CHARM_NAME)

    await ops_test.model.wait_for_idle(
        apps=[
            CONFIG_SERVER_ONE_APP_NAME,
            CONFIG_SERVER_TWO_APP_NAME,
            SHARD_ONE_APP_NAME,
        ],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    await ops_test.model.integrate(
        f"{MONGOS_APP_NAME}",
        f"{MONGOS_HOST_APP_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[MONGOS_HOST_APP_NAME, MONGOS_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
        raise_on_error=False,
    )


async def test_only_one_config_server_relation(ops_test: OpsTest) -> None:
    """Verify that a shard can only be related to one config server."""
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_ONE_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    with pytest.raises(JujuAPIError) as juju_error:
        await ops_test.model.integrate(
            f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
            f"{CONFIG_SERVER_TWO_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
        )

    assert (
        juju_error.value.args[0] == RELATION_LIMIT_MESSAGE
    ), "Shard can relate to multiple config servers."

    # clean up relation
    await ops_test.model.applications[SHARD_ONE_APP_NAME].remove_relation(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_ONE_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[REPLICATION_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )


async def test_cannot_use_db_relation(ops_test: OpsTest) -> None:
    """Verify that sharding components cannot use the DB relation."""
    for sharded_component in SHARDING_COMPONENTS:
        await ops_test.model.integrate(f"{APP_CHARM_NAME}:{DATABASE_REL_NAME}", sharded_component)

    await ops_test.model.wait_for_idle(
        apps=SHARDING_COMPONENTS,
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    for sharded_component in SHARDING_COMPONENTS:
        sharded_component_unit = ops_test.model.applications[sharded_component].units[0]
        assert (
            sharded_component_unit.workload_status_message
            == "Sharding roles do not support database interface."
        ), f"{sharded_component} cannot be related using the database relation"

    # clean up relations
    for sharded_component in SHARDING_COMPONENTS:
        await ops_test.model.applications[sharded_component].remove_relation(
            f"{APP_CHARM_NAME}:{DATABASE_REL_NAME}",
            sharded_component,
        )

    await ops_test.model.wait_for_idle(
        apps=SHARDING_COMPONENTS,
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )


async def test_cannot_use_legacy_db_relation(ops_test: OpsTest) -> None:
    """Verify that sharding components cannot use the legacy DB relation."""
    for sharded_component in SHARDING_COMPONENTS:
        await ops_test.model.integrate(LEGACY_APP_CHARM_NAME, sharded_component)

    await ops_test.model.wait_for_idle(
        apps=SHARDING_COMPONENTS,
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    for sharded_component in SHARDING_COMPONENTS:
        sharded_component_unit = ops_test.model.applications[sharded_component].units[0]
        assert (
            sharded_component_unit.workload_status_message
            == "Sharding roles do not support obsolete interface."
        ), f"{sharded_component} cannot be related using the mongodb relation"

    # clean up relations
    for sharded_component in SHARDING_COMPONENTS:
        await ops_test.model.applications[sharded_component].remove_relation(
            f"{sharded_component}:{LEGACY_RELATION_NAME}",
            f"{LEGACY_APP_CHARM_NAME}:{LEGACY_RELATION_NAME}",
        )

    await ops_test.model.wait_for_idle(
        apps=SHARDING_COMPONENTS,
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )


async def test_replication_config_server_relation(ops_test: OpsTest):
    """Verifies that using a replica as a shard fails."""
    # attempt to add a replication deployment as a shard to the config server.
    await ops_test.model.integrate(
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_ONE_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[REPLICATION_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    replication_unit = ops_test.model.applications[REPLICATION_APP_NAME].units[0]
    assert (
        replication_unit.workload_status_message == "sharding interface cannot be used by replicas"
    ), "replication cannot be related to config server."

    # clean up relations
    await ops_test.model.applications[REPLICATION_APP_NAME].remove_relation(
        f"{REPLICATION_APP_NAME}:{SHARD_REL_NAME}",
        f"{CONFIG_SERVER_ONE_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )


async def test_replication_shard_relation(ops_test: OpsTest):
    """Verifies that using a replica as a config-server fails."""
    # attempt to add a shard to a replication deployment as a config server.
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{REPLICATION_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[REPLICATION_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    replication_unit = ops_test.model.applications[REPLICATION_APP_NAME].units[0]
    assert (
        replication_unit.workload_status_message == "sharding interface cannot be used by replicas"
    ), "replication cannot be related to config server."

    # clean up relation
    await ops_test.model.applications[REPLICATION_APP_NAME].remove_relation(
        f"{SHARD_ONE_APP_NAME}:{SHARD_REL_NAME}",
        f"{REPLICATION_APP_NAME}:{CONFIG_SERVER_REL_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[REPLICATION_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )


async def test_replication_mongos_relation(ops_test: OpsTest) -> None:
    """Verifies connecting a replica to a mongos router fails."""
    # attempt to add a replication deployment as a shard to the config server.
    await ops_test.model.integrate(
        f"{REPLICATION_APP_NAME}",
        f"{MONGOS_APP_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[REPLICATION_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    replication_unit = ops_test.model.applications[REPLICATION_APP_NAME].units[0]
    assert (
        replication_unit.workload_status_message
        == "Relation to mongos not supported, config role must be config-server"
    ), "replica cannot be related to mongos."

    # clean up relations
    await ops_test.model.applications[REPLICATION_APP_NAME].remove_relation(
        f"{REPLICATION_APP_NAME}:cluster",
        f"{MONGOS_APP_NAME}:cluster",
    )

    # TODO remove this and wait for mongos to be active
    # right now we cannot wait for `mongos` to be active after removing the relation due to a bug
    # in the mongos charm. To fix the bug it is first necessary to publish the updated library
    # lib/charms/mongodb/v0/config_server.py
    time.sleep(60)


async def test_shard_mongos_relation(ops_test: OpsTest) -> None:
    """Verifies connecting a shard to a mongos router fails."""
    # attempt to add a replication deployment as a shard to the config server.
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}",
        f"{MONGOS_APP_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[SHARD_ONE_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    shard_unit = ops_test.model.applications[SHARD_ONE_APP_NAME].units[0]
    assert (
        shard_unit.workload_status_message
        == "Relation to mongos not supported, config role must be config-server"
    ), "shard cannot be related to mongos."

    # clean up relations
    await ops_test.model.applications[SHARD_ONE_APP_NAME].remove_relation(
        f"{MONGOS_APP_NAME}:cluster",
        f"{SHARD_ONE_APP_NAME}:cluster",
    )

    await ops_test.model.wait_for_idle(
        apps=[SHARD_ONE_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )


async def test_shard_s3_relation(ops_test: OpsTest) -> None:
    """Verifies connecting a shard to s3-integrator charm fails."""
    # attempt to add a replication deployment as a shard to the config server.
    await ops_test.model.integrate(
        f"{SHARD_ONE_APP_NAME}",
        f"{S3_APP_NAME}",
    )

    await ops_test.model.wait_for_idle(
        apps=[SHARD_ONE_APP_NAME],
        idle_period=20,
        raise_on_blocked=False,
        timeout=TIMEOUT,
    )

    shard_unit = ops_test.model.applications[SHARD_ONE_APP_NAME].units[0]
    assert (
        shard_unit.workload_status_message == "Relation to s3-integrator not supported as shard."
    ), "shard cannot be related to s3-integrator."

    # clean up relations
    await ops_test.model.applications[SHARD_ONE_APP_NAME].remove_relation(
        f"{S3_APP_NAME}:{S3_REL_NAME}",
        f"{SHARD_ONE_APP_NAME}:{S3_REL_NAME}",
    )
