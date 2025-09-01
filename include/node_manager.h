#ifndef NODE_MANAGER_H
#define NODE_MANAGER_H

/**
 * \file node_manager.h
 * \brief Node Manager public API for identity, keys, certs, CA bundle, and signed config in NVS.
 *
 * The Node Manager stores and retrieves materials in NVS, emits esp_event notifications on
 * lifecycle changes, and relies on application-provided callbacks for node id, key generation,
 * signing, CSR generation, and signature verification.
 */

#include "esp_err.h"
#include "esp_event.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h" // for TickType_t

#ifdef __cplusplus
extern "C"
{
#endif

    // Component version
    #define NODE_MANAGER_VERSION_MAJOR 0
    #define NODE_MANAGER_VERSION_MINOR 1
    #define NODE_MANAGER_VERSION_PATCH 0
    #define NODE_MANAGER_VERSION_STRING "0.1.0"

    /**
     * \name Ownership and memory model
     * \brief Conventions for buffer ownership and sensitive data handling.
     * - All store APIs copy input data into NVS; caller retains ownership of its buffers.
     * - All get APIs write into caller-provided buffers or report the required length; no internal pointers are returned.
     * - nm_get_node_id_callback_t returns a pointer to a NUL-terminated string valid for the duration of the call; the
     *   node manager copies it into a local buffer before passing to other callbacks.
     * - Sensitive key material loaded from NVS into RAM is zeroized before being freed.
     */
    /**
     * \brief Signing callback.
     * \details Implemented by a crypto/key component. The node manager provides node identity and key material.
     */
    typedef esp_err_t (*nm_sign_callback_t)(
        const char *node_id,
        const uint8_t *key_der,
        size_t key_der_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *signature_out,
        size_t *sig_len_inout);

    /**
     * \brief Signature verification callback.
     * \details Provided by a TLS/X509 component. Use the provided CA list (DER certificates) to validate the signer.
     */
    typedef esp_err_t (*nm_verify_callback_t)(
        const uint8_t *data,
        size_t data_len,
        const uint8_t *signature,
        size_t sig_len,
        const unsigned char **ca_der_list,
        const size_t *ca_der_lens,
        size_t ca_count);

    /** \brief CSR generation callback. */
    typedef esp_err_t (*nm_csr_callback_t)(
        const char *node_id,
        const uint8_t *key_der,
        size_t key_der_len,
        uint8_t *csr_der_out,
        size_t *csr_der_len_inout);

    /** \brief Retrieve node id callback. Outputs pointer to NUL-terminated string and its length (excluding NUL). */
    typedef esp_err_t (*nm_get_node_id_callback_t)(char **node_id, size_t *len);

    /**
     * \brief Key generation callback.
     * \details Generate a new keypair and return the private key in DER if exportable. If keys are held in secure
     * hardware and cannot be exported, return ESP_OK with privkey_len set to 0.
     */
    typedef esp_err_t (*nm_keygen_callback_t)(uint8_t *privkey_der_out, size_t *privkey_len_inout);

    /** \brief Event base for node manager events. */
    ESP_EVENT_DECLARE_BASE(NODE_MANAGER_EVENT);

    /** \brief Node manager event identifiers. */
    typedef enum
    {
        NM_EVENT_INIT_DONE = 1,
        NM_EVENT_NO_KEY,
        NM_EVENT_NO_CERT,
        NM_EVENT_CSR_AVAILABLE,
        NM_EVENT_CERT_STORED,
        NM_EVENT_KEY_STORED,
        NM_EVENT_CA_BUNDLE_UPDATED,
        NM_EVENT_CONFIG_UPDATED,
        NM_EVENT_ERROR
    } node_manager_event_id_t;

    /** \brief Optional app bus post-event callback. If not provided, esp_event_post is used. */
    typedef esp_err_t (*nm_post_event_callback_t)(
        esp_event_base_t event_base,
        int32_t event_id,
        const void *event_data,
        size_t event_data_size,
        TickType_t ticks_to_wait);

    /** \brief Initialization configuration. */
    typedef struct
    {
        // Callbacks (all optional but recommended)
        nm_get_node_id_callback_t get_node_id_cb; /**< Required for exposing node id */
        nm_keygen_callback_t keygen_cb;           /**< Used if no key is found at init */
        nm_sign_callback_t sign_cb;               /**< For external signing when needed */
        nm_csr_callback_t csr_cb;                 /**< To produce CSR for certificate issuance */
        nm_verify_callback_t verify_cb;           /**< For verifying signed config against CA bundle */

    /** Optional app bus post-event callback. If not provided, esp_event_post is used. */
        nm_post_event_callback_t post_event_cb;

    /** Storage namespace (optional). Defaults to "node_manager" when NULL. */
        const char *nvs_namespace;
    } node_manager_init_config_t;

    /**
     * \brief Initialize the node manager.
     * \details Spawns background init; checks for key/cert presence and emits events. Returns immediately.
     */
    esp_err_t node_manager_init(const node_manager_init_config_t *cfg);

    /** \brief Retrieve node id into caller buffer (includes NUL). */
    esp_err_t node_manager_get_node_id(char *node_id_out, size_t node_id_out_len);

    /** \brief Produce CSR in DER. If csr_der_out is NULL, returns required length via csr_der_len_inout. */
    esp_err_t node_manager_get_csr_der(uint8_t *csr_der_out, size_t *csr_der_len_inout);

    /** \brief Signing helper: calls nm_sign_callback_t with node id and key DER (if available). */
    esp_err_t node_manager_sign(const uint8_t *data, size_t data_len,
                                uint8_t *signature_out, size_t *sig_len_inout);

    /** \brief Store certificate (DER). */
    esp_err_t node_manager_store_cert_der(const uint8_t *cert_der, size_t cert_der_len);
    /** \brief Check if certificate is present. */
    esp_err_t node_manager_has_cert(bool *has_cert_out);
    /** \brief Retrieve certificate (DER). If cert_out is NULL, returns length via cert_len_inout. */
    esp_err_t node_manager_get_cert_der(uint8_t *cert_out, size_t *cert_len_inout);

    /** \brief Set CA list (DER). Accepts an array of DER cert pointers and lengths; stores packed in NVS. */
    esp_err_t node_manager_set_ca_list_der(const unsigned char **ca_der_list, const size_t *ca_der_lens, size_t ca_count);
    /** \brief Check if a CA list is present. */
    esp_err_t node_manager_has_ca_list(bool *has_ca_out);
    /** \brief Retrieve packed CA list blob from NVS. If out is NULL, returns length via len_inout.
     *  Packed format: [count:u32-le] then repeated [len:u32-le][bytes...].
     */
    esp_err_t node_manager_get_ca_list_der_packed(uint8_t *out, size_t *len_inout);

    /** \brief Store signed CBOR config after verification against CA bundle. */
    esp_err_t node_manager_set_signed_config(const uint8_t *cbor_data, size_t cbor_len,
                                             const uint8_t *signature, size_t sig_len);
    /** \brief Retrieve stored CBOR config. If cbor_out is NULL, returns required length. */
    esp_err_t node_manager_get_config(uint8_t *cbor_out, size_t *cbor_len_inout);
    /** \brief Clear stored CBOR config. */
    esp_err_t node_manager_clear_config(void);

    /** \brief Store config without verification (e.g., development). Emits NM_EVENT_CONFIG_UPDATED on success. */
    esp_err_t node_manager_set_config_unverified(const uint8_t *cbor_data, size_t cbor_len);

    /** \brief Check if private key is present. */
    esp_err_t node_manager_has_key(bool *has_key_out);
    /** \brief Store private key in DER format. */
    esp_err_t node_manager_set_key_der(const uint8_t *der, size_t der_len);
    /** \brief Retrieve private key (DER). If der_out is NULL, returns length via der_len_inout. */
    esp_err_t node_manager_get_key_der(uint8_t *der_out, size_t *der_len_inout);

    /** \brief Clear stored key and regenerate via keygen_cb if provided.
     *  \details Events: emits NM_EVENT_NO_KEY prior to regeneration, then NM_EVENT_KEY_STORED on success. Also emits
     *  NM_EVENT_NO_CERT and NM_EVENT_CSR_AVAILABLE after regeneration to trigger re-provisioning.
     */
    esp_err_t node_manager_reset_key_and_regen(void);

    /** \brief Clear both stored certificate and CA bundle in one call.
     *  \details Events: emits NM_EVENT_NO_CERT and NM_EVENT_CA_BUNDLE_UPDATED. If CSR is supported, emits NM_EVENT_CSR_AVAILABLE.
     */
    esp_err_t node_manager_clear_certs(void);

#ifdef __cplusplus
}
#endif

#endif // NODE_MANAGER_H