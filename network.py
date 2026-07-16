PRIVATE_NETWORKS = {

    "10.0.0.0/8": {
        "description": "Private Class A network."
    },

    "172.16.0.0/12": {
        "description": "Private Class B network."
    },

    "192.168.0.0/16": {
        "description": "Private Class C network."
    }

}

LOOPBACK_NETWORKS = {

    "127.0.0.0/8": {
        "description": "Loopback network."
    }

}

LINK_LOCAL_NETWORKS = {

    "169.254.0.0/16": {
        "description": "Automatic Private IP Addressing (APIPA)."
    }

}

MULTICAST_NETWORKS = {

    "224.0.0.0/4": {
        "description": "IPv4 multicast."
    }

}

RESERVED_NETWORKS = {

    "0.0.0.0/8": {
        "description": "Reserved address range."
    },

    "240.0.0.0/4": {
        "description": "Reserved for future use."
    }

}

DOCUMENTATION_NETWORKS = {

    "192.0.2.0/24": {
        "description": "TEST-NET-1."
    },

    "198.51.100.0/24": {
        "description": "TEST-NET-2."
    },

    "203.0.113.0/24": {
        "description": "TEST-NET-3."
    }

}

CGNAT_NETWORKS = {

    "100.64.0.0/10": {
        "description": "Carrier Grade NAT."
    }

}

IPV6_SPECIAL_NETWORKS = {

    "::1/128": {
        "description": "IPv6 loopback."
    },

    "fc00::/7": {
        "description": "IPv6 unique local address."
    },

    "fe80::/10": {
        "description": "IPv6 link-local."
    }

}


