# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class we manage client database relations.

This class creates user and database for each application relation
and expose needed information for client connection via fields in
external relation.
"""
import base64
import logging
import re
import socket
from typing import List, Optional, Tuple

from charms.mongodb.v0.mongodb import MongoDBConnection
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    TLSCertificatesRequiresV1,
    generate_csr,
    generate_private_key,
)
from ops.model import Application
from ops.charm import ActionEvent, RelationBrokenEvent, RelationJoinedEvent
from ops.framework import Object
from ops.model import ActiveStatus, MaintenanceStatus, Unit, WaitingStatus

from config import Config

APP_SCOPE = Config.Relations.APP_SCOPE
UNIT_SCOPE = Config.Relations.UNIT_SCOPE
Scopes = Config.Relations.Scopes


# The unique Charmhub library identifier, never change it
LIBID = "e02a50f0795e4dd292f58e93b4f493dd"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 7

logger = logging.getLogger(__name__)


class MongoDBTLS(Object):
    """In this class we manage client database relations."""

    def __init__(self, charm, peer_relation, substrate):
        """Manager of MongoDB client relations."""
        super().__init__(charm, "client-relations")
        self.charm = charm
        self.substrate = substrate
        self.peer_relation = peer_relation
        self.certs = TLSCertificatesRequiresV1(self.charm, Config.TLS.TLS_PEER_RELATION)
        self.framework.observe(
            self.charm.on.set_tls_private_key_action, self._on_set_tls_private_key
        )
        self.framework.observe(
            self.charm.on[Config.TLS.TLS_PEER_RELATION].relation_joined,
            self._on_tls_relation_joined,
        )
        self.framework.observe(
            self.charm.on[Config.TLS.TLS_PEER_RELATION].relation_broken,
            self._on_tls_relation_broken,
        )
        self.framework.observe(self.certs.on.certificate_available, self._on_certificate_available)
        self.framework.observe(self.certs.on.certificate_expiring, self._on_certificate_expiring)

    def is_tls_enabled(self, scope: Scopes):
        """Returns a boolean indicating if TLS for a given `scope` is enabled."""
        # this should be fixdd wihtout any needed changes as soon as we set the secrets in the sharding relation interface
        return self.charm.get_secret(scope, Config.TLS.SECRET_CERT_LABEL) is not None

    def _on_set_tls_private_key(self, event: ActionEvent) -> None:
        """Set the TLS private key, which will be used for requesting the certificate."""
        logger.debug("Request to set TLS private key received.")
        if self.shard_must_wait_for_config_server():
            event.fail("TLS cannot be enabled until shard is integrated with config-server")

        try:
            self._request_certificate(UNIT_SCOPE, event.params.get("external-key", None))

            if not self.charm.unit.is_leader():
                event.log(
                    "Only juju leader unit can set private key for the internal certificate. Skipping."
                )
                return
            if self.charm.is_role(Config.Role.SHARD):
                event.log(
                    "Only the config-server can set the private key for the internal certifcate. Skipping."
                )
                return

            self._request_certificate(APP_SCOPE, event.params.get("internal-key", None))
            logger.debug("Successfully set TLS private key.")
        except ValueError as e:
            event.fail(str(e))

    def _get_subject_name(self):
        """Retrieve the subject name used in the CSR."""
        # In sharding, MongoDB requries that all shards use the same subject name in their CSRs.
        if self.charm.is_role(Config.Role.SHARD):
            return self.charm.shard.get_config_server_name()

        return self.charm.app.name

    def _request_certificate(self, scope: Scopes, param: Optional[str]):
        if param is None:
            key = generate_private_key()
        else:
            key = self._parse_tls_file(param)

        subject = self._get_subject_name()
        if scope == APP_SCOPE:
            csr = generate_csr(
                private_key=key,
                subject=subject,
                organization=subject,
                sans=self._get_app_sans(),
                sans_ip=[
                    str(self.charm.model.get_binding(self.peer_relation).network.bind_address)
                ],
            )
        elif scope == UNIT_SCOPE:
            csr = generate_csr(
                private_key=key,
                subject=subject,
                organization=subject,
                sans=self._get_unit_sans(),
                sans_ip=[
                    str(self.charm.model.get_binding(self.peer_relation).network.bind_address)
                ],
            )
        else:
            raise NotImplementedError

        self.charm.set_secret(scope, Config.TLS.SECRET_KEY_LABEL, key.decode("utf-8"))
        self.charm.set_secret(scope, Config.TLS.SECRET_CSR_LABEL, csr.decode("utf-8"))
        self.charm.set_secret(scope, Config.TLS.SECRET_CERT_LABEL, None)

        if self.charm.model.get_relation(Config.TLS.TLS_PEER_RELATION):
            self.certs.request_certificate_creation(certificate_signing_request=csr)

    @staticmethod
    def _parse_tls_file(raw_content: str) -> bytes:
        """Parse TLS files from both plain text or base64 format."""
        if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", raw_content):
            return (
                re.sub(
                    r"(-+(BEGIN|END) [A-Z ]+-+)",
                    "\\1",
                    raw_content,
                )
                .rstrip()
                .encode("utf-8")
            )
        return base64.b64decode(raw_content)

    def shard_must_wait_for_config_server(self):
        return (
            self.charm.is_role(Config.Role.SHARD) and not self.charm.shard.get_config_server_name()
        )

    def _on_tls_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Request certificate when TLS relation joined."""
        if self.shard_must_wait_for_config_server():
            event.defer()
            logger.debug("TLS cannot be enabled until shard is integrated with config-server")
            return

        # Shards use the same internal certs set by the config-server
        if (
            self.charm.unit.is_leader()
        ):  # TODO get anser for this and not self.charm.is_role(Config.Role.SHARD):
            self._request_certificate(APP_SCOPE, None)

        self._request_certificate(UNIT_SCOPE, None)

    def _on_tls_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Disable TLS when TLS relation broken."""
        logger.debug("Disabling external TLS for unit: %s", self.charm.unit.name)
        self.charm.set_secret(UNIT_SCOPE, Config.TLS.SECRET_CA_LABEL, None)
        self.charm.set_secret(UNIT_SCOPE, Config.TLS.SECRET_CERT_LABEL, None)
        self.charm.set_secret(UNIT_SCOPE, Config.TLS.SECRET_CHAIN_LABEL, None)

        if self.charm.unit.is_leader():
            logger.debug("Disabling internal TLS")
            self.charm.set_secret(APP_SCOPE, Config.TLS.SECRET_CA_LABEL, None)
            self.charm.set_secret(APP_SCOPE, Config.TLS.SECRET_CERT_LABEL, None)
            self.charm.set_secret(APP_SCOPE, Config.TLS.SECRET_CHAIN_LABEL, None)

        if self.charm.get_secret(APP_SCOPE, Config.TLS.SECRET_CERT_LABEL):
            logger.debug(
                "Defer until the leader deletes the internal TLS certificate to avoid second restart."
            )
            event.defer()
            return

        logger.info("Restarting mongod with TLS disabled.")
        self.charm.unit.status = MaintenanceStatus("disabling TLS")
        self.charm.delete_tls_certificate_from_workload()
        self.charm.restart_mongod_service()
        self.charm.unit.status = ActiveStatus()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Enable TLS when TLS certificate available."""
        unit_csr = self.charm.get_secret(UNIT_SCOPE, Config.TLS.SECRET_CSR_LABEL)
        app_csr = self.charm.get_secret(APP_SCOPE, Config.TLS.SECRET_CSR_LABEL)

        if unit_csr and event.certificate_signing_request.rstrip() == unit_csr.rstrip():
            logger.debug("The external TLS certificate available.")
            scope = UNIT_SCOPE  # external crs
        elif app_csr and event.certificate_signing_request.rstrip() == app_csr.rstrip():
            logger.debug("The internal TLS certificate available.")
            scope = APP_SCOPE  # internal crs
        else:
            logger.error("An unknown certificate is available -- ignoring.")
            return

        if scope == UNIT_SCOPE or (scope == APP_SCOPE and self.charm.unit.is_leader()):
            self.charm.set_secret(
                scope,
                Config.TLS.SECRET_CHAIN_LABEL,
                "\n".join(event.chain) if event.chain is not None else None,
            )
            self.charm.set_secret(scope, Config.TLS.SECRET_CERT_LABEL, event.certificate)
            self.charm.set_secret(scope, Config.TLS.SECRET_CA_LABEL, event.ca)

        if self.charm.is_role(Config.Role.CONFIG_SERVER):
            # TODO notify all shards of new internal certs
            pass

        if self._waiting_for_certs():
            logger.debug(
                "Defer until both internal and external TLS certificates available to avoid second restart."
            )
            event.defer()
            return

        logger.info("Restarting mongod with TLS enabled.")

        self.charm.delete_tls_certificate_from_workload()
        self.charm.push_tls_certificate_to_workload()
        self.charm.unit.status = MaintenanceStatus("enabling TLS")
        self.charm.restart_mongod_service()

        with MongoDBConnection(self.charm.mongodb_config) as mongo:
            if not mongo.is_ready:
                self.charm.unit.status = WaitingStatus("Waiting for MongoDB to start")
            else:
                self.charm.unit.status = ActiveStatus()

    def _waiting_for_certs(self):
        """Returns a boolean indicating whether additional certs are needed."""
        if not self.charm.is_role(Config.Role.SHARD) and not self.charm.get_secret(
            APP_SCOPE, Config.TLS.SECRET_CERT_LABEL
        ):
            logger.debug("Waiting for application certificate.")
            return True
        if not self.charm.get_secret(UNIT_SCOPE, Config.TLS.SECRET_CERT_LABEL):
            logger.debug("Waiting for application certificate.")
            return True

        return False

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """Request the new certificate when old certificate is expiring."""
        # TODO copy over Mykola's solution
        if (
            event.certificate.rstrip()
            == self.charm.get_secret(UNIT_SCOPE, Config.TLS.SECRET_CERT_LABEL).rstrip()
        ):
            logger.debug("The external TLS certificate expiring.")
            scope = UNIT_SCOPE  # external cert
        elif (
            event.certificate.rstrip()
            == self.charm.get_secret(APP_SCOPE, Config.TLS.SECRET_CERT_LABEL).rstrip()
        ):
            logger.debug("The internal TLS certificate expiring.")
            if not self.charm.unit.is_leader():
                return
            scope = APP_SCOPE  # internal cert
        else:
            logger.error("An unknown certificate expiring.")
            return

        logger.debug("Generating a new Certificate Signing Request.")
        key = self.charm.get_secret(scope, Config.TLS.SECRET_KEY_LABEL).encode("utf-8")
        old_csr = self.charm.get_secret(scope, Config.TLS.SECRET_CSR_LABEL).encode("utf-8")
        new_csr = generate_csr(
            private_key=key,
            subject=self.get_host(self.charm.unit),
            organization=self.charm.app.name,
            sans=self._get_sans(external=scope == UNIT_SCOPE),
            sans_ip=[str(self.charm.model.get_binding(self.peer_relation).network.bind_address)],
        )
        logger.debug("Requesting a certificate renewal.")

        self.certs.request_certificate_renewal(
            old_certificate_signing_request=old_csr,
            new_certificate_signing_request=new_csr,
        )

        self.charm.set_secret(scope, Config.TLS.SECRET_CSR_LABEL, new_csr.decode("utf-8"))

    def _get_unit_sans(self) -> List[str]:
        """Create a list of DNS names for a MongoDB unit.

        Returns:
            A list representing the hostnames of the MongoDB unit.
        """
        unit_id = self.charm.unit.name.split("/")[1]

        return [
            f"{self.charm.app.name}-{unit_id}",
            f"*.{self.charm.app.name}-{unit_id}",
            socket.getfqdn(),
            f"{self.charm.app.name}-{unit_id}.{self.charm.app.name}-endpoints",
            str(self.charm.model.get_binding(self.peer_relation).network.bind_address),
        ]

    def _get_app_sans(self) -> List[str]:
        """Create a list of DNS names for a MongoDB unit.
        Returns:
            A list representing the hostnames of the MongoDB unit.
        """
        return [
            f"config-server-*",
            f"config-server-*.config-server-endpoints",
        ]

    def _generate_shard_sans(self, shard_relation):
        shard_app_name = shard_relation.app.name
        shard_host = self.charm.config_server._get_shard_hosts(shard_app_name)[0]
        shard_units = list(shard_relation.units)
        shard_unit_id = shard_units[0].name.split("/")[1]
        return [
            f"{shard_app_name}-{shard_unit_id}",
            f"*.{shard_app_name}-{shard_unit_id}",
            f"{shard_app_name}-{shard_unit_id}.{shard_app_name}-endpoints",
            str(shard_host),
        ]

    def get_tls_files(self, scope: Scopes) -> Tuple[Optional[str], Optional[str]]:
        """Prepare TLS files in special MongoDB way.

        MongoDB needs two files:
        — CA file should have a full chain.
        — PEM file should have private key and certificate without certificate chain.
        """
        if not self.is_tls_enabled(scope):
            logging.debug(f"TLS disabled for {scope}")
            return None, None
        logging.debug(f"TLS *enabled* for {scope}, fetching data for CA and PEM files ")

        ca = self.charm.get_secret(scope, Config.TLS.SECRET_CA_LABEL)
        chain = self.charm.get_secret(scope, Config.TLS.SECRET_CHAIN_LABEL)
        ca_file = chain if chain else ca

        key = self.charm.get_secret(scope, Config.TLS.SECRET_KEY_LABEL)
        cert = self.charm.get_secret(scope, Config.TLS.SECRET_CERT_LABEL)
        pem_file = key
        if cert:
            pem_file = key + "\n" + cert if key else cert

        return ca_file, pem_file

    def get_host(self, unit: Unit):
        """Retrieves the hostname of the unit based on the substrate."""
        if self.substrate == "vm":
            return self.charm._unit_ip(unit)
        else:
            return self.charm.get_hostname_for_unit(unit)
