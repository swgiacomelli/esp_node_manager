# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2025-09-01
- Initial public release of node_manager as an ESP-IDF component.
- NVS-backed storage for key, cert, CA bundle, and CBOR config.
- Events via esp_event for key/cert/config lifecycle.
- Pluggable callbacks for node id, keygen, sign, CSR, and verification.