# node_manager (ESP-IDF component)

Manage node identity, private key, device certificate, CA bundle, and a signed CBOR config stored in NVS. Emits esp_event notifications for lifecycle changes (key/cert/config updates) and supports pluggable callbacks for keygen, signing, CSR creation, and signature verification.

## Features
- NVS-backed storage for private key (DER), certificate (DER), CA bundle (packed DER list), and config (CBOR)
- Events via `NODE_MANAGER_EVENT` covering init, key/cert presence, CSR availability, config updates, and errors
- Pluggable callbacks:
  - get node id
  - key generation
  - sign and CSR generation
  - verification of signed config against CA bundle
- Careful handling of sensitive buffers (zeroization of temporary key material)

## Requirements
- ESP-IDF >= 5.0
- `nvs_flash` and `esp_event` (provided by IDF)

## **Security disclaimer**
- This component does not provide at-rest encryption for private keys by itself. Storing sensitive keys in NVS without additional protections is not secure for production devices. Enable ESP-IDF security features such as NVS encryption, Flash Encryption, and Secure Boot as appropriate for your threat model.

## Install

### Option A: Git submodule (recommended)
Add the component to your project:

```sh
git submodule add https://github.com/swgiacomelli/esp_node_manager components/node_manager
```

ESP-IDF will discover components under `components/` automatically.

### Option B: Component Manager via Git URL (no registry)
If you use the ESP-IDF Component Manager, you can depend on a Git URL directly in your project's `idf_component.yml`:

```yaml
dependencies:
    node_manager:
        git: https://github.com/swgiacomelli/esp_node_manager
        version: "^0.1.0"
```


## Quick start
```c
#include "node_manager.h"

static esp_err_t my_get_id(char **out, size_t *len) { static char id[] = "node-123"; *out = id; *len = strlen(id); return ESP_OK; }

void app_main(void) {
    node_manager_init_config_t cfg = {
        .get_node_id_cb = my_get_id,
        .keygen_cb = NULL,            // optional
        .sign_cb = NULL,              // optional
        .csr_cb = NULL,               // optional
        .verify_cb = NULL,            // optional
        .post_event_cb = NULL,        // optional
        .nvs_namespace = NULL         // defaults to "node_manager"
    };
    ESP_ERROR_CHECK(node_manager_init(&cfg));
}
```

See `examples/simple` for a minimal application.

## API surface
Public headers are in `include/node_manager.h`. The main calls include:
- init: `node_manager_init`
- node id: `node_manager_get_node_id`
- key: `node_manager_has_key`, `node_manager_set_key_der`, `node_manager_get_key_der`, `node_manager_reset_key_and_regen`
- cert: `node_manager_store_cert_der`, `node_manager_has_cert`, `node_manager_get_cert_der`, `node_manager_clear_certs`
- CA bundle: `node_manager_set_ca_list_der`, `node_manager_has_ca_list`, `node_manager_get_ca_list_der_packed`
- CSR/sign: `node_manager_get_csr_der`, `node_manager_sign`
- config: `node_manager_set_signed_config`, `node_manager_set_config_unverified`, `node_manager_get_config`, `node_manager_clear_config`

## Events
The component declares `ESP_EVENT_DECLARE_BASE(NODE_MANAGER_EVENT)`. Event IDs:
- `NM_EVENT_INIT_DONE`, `NM_EVENT_NO_KEY`, `NM_EVENT_NO_CERT`, `NM_EVENT_CSR_AVAILABLE`,
- `NM_EVENT_CERT_STORED`, `NM_EVENT_KEY_STORED`, `NM_EVENT_CA_BUNDLE_UPDATED`, `NM_EVENT_CONFIG_UPDATED`, `NM_EVENT_ERROR`.

## Versioning
This is pre-release software. Semantic version 0.1.0.

## License

ISC — see `LICENSE`.
