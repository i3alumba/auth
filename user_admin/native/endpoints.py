"""Operator-approved plaintext origins; never infer private trust from DNS/IP."""

from types import MappingProxyType

CLUSTER_HTTP_ORIGINS = MappingProxyType(
    {
        "gitlab": "http://gitlab.public-page.svc.cluster.local",
        "matrix": "http://synapse.public-page.svc.cluster.local:8008",
        "minio": "http://minio.public-page.svc.cluster.local:9000",
    }
)


def is_cluster_http_origin(service: str, origin: str) -> bool:
    return (
        type(service) is str
        and type(origin) is str
        and service in CLUSTER_HTTP_ORIGINS
        and origin == CLUSTER_HTTP_ORIGINS[service]
    )
