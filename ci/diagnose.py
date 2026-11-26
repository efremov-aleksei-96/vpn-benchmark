"""Public CI diagnostic classifier. Never print input or raw application logs."""
import sys

RULES = (
    ("unix_socket_ownership", ("update server unix domain socket permission failed", "os.chown(", "chown failed")),
    ("permission_denied", ("operation not permitted", "permission denied", "access denied")),
    ("read_only_filesystem", ("read-only file system",)),
    ("address_in_use", ("address already in use",)),
    ("address_unavailable", ("cannot assign requested address",)),
    ("missing_file_or_directory", ("no such file or directory", "file not exist", "file does not exist")),
    ("config_parse_or_validation", ("invalid config", "failed to validate", "validatefullserverconfig", "unmarshal", "unknown field", "unknown enum", "decode config", "loadserverconfig", "load server config")),
    ("certificate_error", ("failed to load certificate", "invalid certificate", "tls:", "x509:")),
    ("listener_start_failed", ("listen on rpc address", "start mita server proxy failed", "start inbound", "failed to listen", "bind:")),
    ("rpc_not_ready", ("connection refused", "rpc error")),
    ("runtime_failure", ("panic:", "fatal error:", "segmentation fault", "out of memory")),
)

def classify(data):
    lower = data.lower()
    return [label for label, patterns in RULES if any(p in lower for p in patterns)]

def main():
    data = sys.stdin.read()
    labels = classify(data)
    print("diagnostic_categories=" + (",".join(labels) if labels else "unclassified"))
    print("raw_log_lines=" + str(len(data.splitlines())) + " (content withheld)")
    # Only fixed synthetic addresses and port labels; no arbitrary log substrings.
    for addr in ("198.18.254.1", "172.30.241.2", "172.30.242.2"):
        for port in (18443,18444,18445):
            if f"{addr}:{port}" in data:
                print("synthetic_endpoint_mentioned="+addr+":"+str(port))
    for label, marker in (("port_mapping","port mapping"),("host_port","host port"),("userland_proxy","userland proxy"),("external_connectivity","external connectivity"),("network_endpoint","endpoint")):
        if marker in data.lower(): print("docker_context="+label)

if __name__ == "__main__":
    main()
