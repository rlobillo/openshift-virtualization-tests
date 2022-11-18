from ocp_resources.cdi import CDI
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.ssp import SSP


MANAGED_CRS_LIST = [KubeVirt, CDI, NetworkAddonsConfig, SSP]

INTERMEDIATE_POLICY = "intermediate"
TLS_INTERMEDIATE_PROFILE = {INTERMEDIATE_POLICY: {}, "type": "Intermediate"}

RESOURCE_TYPE_STR = "resource_type"
RESOURCE_NAME_STR = "resource_name"
EXPECTED_VALUE_STR = "expected_value"
RESOURCE_NAMESPACE_STR = "resource_namespace"


TLS_SECURITY_PROFILE = "tlsSecurityProfile"

KEY_NAME_STR = "key_name"
CRYPTO_POLICY_EXPECTED_DICT = {
    INTERMEDIATE_POLICY: {
        KubeVirt: {
            "ciphers": [
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            ],
            "minTLSVersion": "VersionTLS12",
        },
        SSP: TLS_INTERMEDIATE_PROFILE,
        CDI: TLS_INTERMEDIATE_PROFILE,
        NetworkAddonsConfig: TLS_INTERMEDIATE_PROFILE,
    },
}
