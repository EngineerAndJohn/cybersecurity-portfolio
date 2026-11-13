"""wqe7002-recon: bounded Scapy TCP SYN scanner for the WQE7002 course lab.

Pure-Scapy implementation.  Nmap is never invoked by this package; it is used
only as an independent comparison tool during the validation experiment.
"""

__version__ = "1.0.0"
TOOL_NAME = "wqe7002-recon"
SUPPORTED_OPTION = "tcp-syn-scan"

# Hard bounds enforced on top of whatever the scope manifest declares.
HARD_MAX_RATE_PPS = 20
HARD_MAX_ATTEMPTS = 2
HARD_MAX_PORTS = 30
HARD_MAX_TIMEOUT_S = 10.0
