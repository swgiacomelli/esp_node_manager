// Node Manager implementation

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "node_manager.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "nvs.h"

// Logging tag must be available before macros use it
static const char *TAG = "node_manager";

// Event base definition
ESP_EVENT_DEFINE_BASE(NODE_MANAGER_EVENT);

#define NM_NVS_DEFAULT_NAMESPACE "node_manager"
#define NM_INIT_TASK_STACK 8192 // key generation needs more stack
#define NM_INIT_TASK_PRIO (tskIDLE_PRIORITY + 2)
#define NM_INIT_TASK_CORE tskNO_AFFINITY

// Init readiness bit (event group)
#define NM_READY_BIT (1 << 0)

// NVS keys
#define NM_NVS_KEY_PRIVKEY "privkey"
#define NM_NVS_KEY_CERT "cert"
#define NM_NVS_KEY_CA_LIST "ca_list"
#define NM_NVS_KEY_CONFIG "config"

typedef struct
{
	nm_get_node_id_callback_t get_node_id_cb;
	nm_keygen_callback_t keygen_cb;
	nm_sign_callback_t sign_cb;
	nm_csr_callback_t csr_cb;
	nm_verify_callback_t verify_cb;
	const char *nvs_ns;
	nvs_handle_t nvs;
	nm_post_event_callback_t post_event_cb;
} nm_ctx_t;

static nm_ctx_t s_nm = {0};
static SemaphoreHandle_t s_nvs_mutex = NULL;
static EventGroupHandle_t s_ready_eg = NULL;

static inline void nm_nvs_lock(void)
{
	if (s_nvs_mutex)
	{
		xSemaphoreTake(s_nvs_mutex, portMAX_DELAY);
	}
}

static inline void nm_nvs_unlock(void)
{
	if (s_nvs_mutex)
	{
		xSemaphoreGive(s_nvs_mutex);
	}
}

static inline esp_err_t nm_wait_ready_blocking(void)
{
	if (!s_ready_eg)
		return ESP_ERR_INVALID_STATE;
	(void)xEventGroupWaitBits(s_ready_eg, NM_READY_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
	return ESP_OK;
}

// Secure zeroization helpers (avoid being optimized out)
static void nm_secure_memzero(void *v, size_t n)
{
	if (!v || n == 0)
		return;
	volatile uint8_t *p = (volatile uint8_t *)v;
	while (n--)
	{
		*p++ = 0;
	}
}

static void nm_secure_free(void *v, size_t n)
{
	if (v && n)
		nm_secure_memzero(v, n);
	free(v);
}

static esp_err_t nm_open_nvs(const char *ns, nvs_handle_t *handle_out)
{
	const char *use_ns = (ns && ns[0]) ? ns : NM_NVS_DEFAULT_NAMESPACE;
	return nvs_open(use_ns, NVS_READWRITE, handle_out);
}

static esp_err_t nm_read_blob_len(nvs_handle_t nvs, const char *key, size_t *len_out)
{
	esp_err_t err = nvs_get_blob(nvs, key, NULL, len_out);
	if (err == ESP_ERR_NVS_NOT_FOUND)
	{
		*len_out = 0;
		return ESP_OK;
	}
	return err;
}

static bool nm_blob_exists(nvs_handle_t nvs, const char *key)
{
	size_t len = 0;
	esp_err_t err = nvs_get_blob(nvs, key, NULL, &len);
	return (err == ESP_OK && len > 0);
}

static esp_err_t nm_emit_event(node_manager_event_id_t id)
{
	if (s_nm.post_event_cb)
	{
		return s_nm.post_event_cb(NODE_MANAGER_EVENT, id, NULL, 0, portMAX_DELAY);
	}
	return esp_event_post(NODE_MANAGER_EVENT, id, NULL, 0, portMAX_DELAY);
}

static esp_err_t nm_store_blob(const char *key, const void *data, size_t len)
{
	if (s_nm.nvs == 0)
		return ESP_ERR_INVALID_STATE;
	// Caller should hold nm_nvs_lock when calling this function in public APIs.
	esp_err_t err = nvs_set_blob(s_nm.nvs, key, data, len);
	if (err != ESP_OK)
		return err;
	return nvs_commit(s_nm.nvs);
}

// Write a 32-bit value in little-endian order
static inline void nm_put_u32_le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void nm_init_task(void *arg)
{
	// Ensure NVS is initialized by the app; if not, init here.
	esp_err_t err = nvs_flash_init();
	if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
	{
		nvs_flash_erase();
		err = nvs_flash_init();
	}
	if (err != ESP_OK)
	{
		nm_emit_event(NM_EVENT_ERROR);
		if (s_ready_eg)
			xEventGroupSetBits(s_ready_eg, NM_READY_BIT);
		vTaskDelete(NULL);
		return;
	}

	// Open NVS namespace
	err = nm_open_nvs(s_nm.nvs_ns, &s_nm.nvs);
	if (err != ESP_OK)
	{
		nm_emit_event(NM_EVENT_ERROR);
		if (s_ready_eg)
			xEventGroupSetBits(s_ready_eg, NM_READY_BIT);
		vTaskDelete(NULL);
		return;
	}

	// Check key presence
	bool has_key = nm_blob_exists(s_nm.nvs, NM_NVS_KEY_PRIVKEY);
	if (!has_key)
	{
		// Generate key if callback provided
		if (s_nm.keygen_cb)
		{
			uint8_t buf[2048];
			size_t len = sizeof(buf);
			esp_err_t kerr = s_nm.keygen_cb(buf, &len);
			if (kerr != ESP_OK)
			{
				nm_secure_memzero(buf, sizeof(buf));
				nm_emit_event(NM_EVENT_ERROR);
				if (s_ready_eg)
					xEventGroupSetBits(s_ready_eg, NM_READY_BIT);
				vTaskDelete(NULL);
				return;
			}
			if (len > 0)
			{
				esp_err_t serr = nm_store_blob(NM_NVS_KEY_PRIVKEY, buf, len);
				// Zeroize the stack buffer regardless of store result
				nm_secure_memzero(buf, len);
				if (serr != ESP_OK)
				{
					nm_emit_event(NM_EVENT_ERROR);
					if (s_ready_eg)
						xEventGroupSetBits(s_ready_eg, NM_READY_BIT);
					vTaskDelete(NULL);
					return;
				}
				nm_emit_event(NM_EVENT_KEY_STORED);
			}
			else
			{
				// No exportable key; still wipe entire buffer
				nm_secure_memzero(buf, sizeof(buf));
			}
		}
		else
		{
			nm_emit_event(NM_EVENT_NO_KEY);
		}
	}

	// Cert presence
	bool has_cert = nm_blob_exists(s_nm.nvs, NM_NVS_KEY_CERT);
	if (!has_cert)
	{
		nm_emit_event(NM_EVENT_NO_CERT);
		// If we can produce CSR, emit availability immediately
		if (s_nm.csr_cb)
		{
			nm_emit_event(NM_EVENT_CSR_AVAILABLE);
		}
	}

	// Mark ready then emit INIT_DONE
	if (s_ready_eg)
		xEventGroupSetBits(s_ready_eg, NM_READY_BIT);
	nm_emit_event(NM_EVENT_INIT_DONE);
	vTaskDelete(NULL);
}

esp_err_t node_manager_init(const node_manager_init_config_t *cfg)
{
	if (cfg == NULL)
		return ESP_ERR_INVALID_ARG;

	// Save callbacks
	memset(&s_nm, 0, sizeof(s_nm));
	s_nm.get_node_id_cb = cfg->get_node_id_cb;
	s_nm.keygen_cb = cfg->keygen_cb;
	s_nm.sign_cb = cfg->sign_cb;
	s_nm.csr_cb = cfg->csr_cb;
	s_nm.verify_cb = cfg->verify_cb;
	s_nm.nvs_ns = (cfg->nvs_namespace && cfg->nvs_namespace[0]) ? cfg->nvs_namespace : NM_NVS_DEFAULT_NAMESPACE;
	s_nm.post_event_cb = cfg->post_event_cb;

	// Create synchronization primitives
	s_nvs_mutex = xSemaphoreCreateMutex();
	if (!s_nvs_mutex)
	{
		return ESP_ERR_NO_MEM;
	}
	s_ready_eg = xEventGroupCreate();
	if (!s_ready_eg)
	{
		vSemaphoreDelete(s_nvs_mutex);
		s_nvs_mutex = NULL;
		return ESP_ERR_NO_MEM;
	}

	// Spawn background init task and return immediately
	BaseType_t ok = xTaskCreatePinnedToCore(nm_init_task, "nm_init", NM_INIT_TASK_STACK, NULL,
											NM_INIT_TASK_PRIO, NULL, NM_INIT_TASK_CORE);
	return ok == pdPASS ? ESP_OK : ESP_FAIL;
}

esp_err_t node_manager_get_node_id(char *node_id_out, size_t node_id_out_len)
{
	if (!node_id_out || node_id_out_len == 0)
		return ESP_ERR_INVALID_ARG;
	if (!s_nm.get_node_id_cb)
		return ESP_ERR_INVALID_STATE;
	char *nid = NULL;
	size_t nlen = 0;
	esp_err_t err = s_nm.get_node_id_cb(&nid, &nlen);
	if (err != ESP_OK)
		return err;
	if (!nid)
		return ESP_ERR_INVALID_STATE;
	size_t need = nlen + 1; // include NUL
	if (node_id_out_len < need)
		return ESP_ERR_NO_MEM;
	memcpy(node_id_out, nid, need);
	return ESP_OK;
}

esp_err_t node_manager_get_csr_der(uint8_t *csr_der_out, size_t *csr_der_len_inout)
{
	if (!csr_der_len_inout)
		return ESP_ERR_INVALID_ARG;
	if (!s_nm.csr_cb)
		return ESP_ERR_INVALID_STATE;
	if (!s_nm.get_node_id_cb)
		return ESP_ERR_INVALID_STATE;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;

	char node_id[128];
	char *nid = NULL;
	size_t nlen = 0;
	esp_err_t err = s_nm.get_node_id_cb(&nid, &nlen);
	if (err != ESP_OK)
		return err;
	size_t need = nlen + 1;
	if (need > sizeof node_id)
		return ESP_ERR_NO_MEM;
	memcpy(node_id, nid, need);

	size_t der_len = 0;
	err = node_manager_get_key_der(NULL, &der_len);
	if (err != ESP_OK)
		return err;
	uint8_t *der = (uint8_t *)malloc(der_len);
	if (!der)
		return ESP_ERR_NO_MEM;
	err = node_manager_get_key_der(der, &der_len);
	if (err != ESP_OK)
	{
		nm_secure_free(der, der_len);
		return err;
	}

	// First ask callback for size if caller provided NULL
	if (!csr_der_out)
	{
		size_t want = 0;
		err = s_nm.csr_cb(node_id, der, der_len, NULL, &want);
		nm_secure_free(der, der_len);
		if (err != ESP_OK)
			return err;
		*csr_der_len_inout = want;
		return ESP_OK;
	}
	err = s_nm.csr_cb(node_id, der, der_len, csr_der_out, csr_der_len_inout);
	nm_secure_free(der, der_len);
	return err;
}

esp_err_t node_manager_sign(const uint8_t *data, size_t data_len,
							uint8_t *signature_out, size_t *sig_len_inout)
{
	if (!data || data_len == 0 || !signature_out || !sig_len_inout)
		return ESP_ERR_INVALID_ARG;
	if (!s_nm.sign_cb)
		return ESP_ERR_INVALID_STATE;
	if (!s_nm.get_node_id_cb)
		return ESP_ERR_INVALID_STATE;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;

	char node_id[128];
	char *nid = NULL;
	size_t nlen = 0;
	esp_err_t err = s_nm.get_node_id_cb(&nid, &nlen);
	if (err != ESP_OK)
		return err;
	size_t need = nlen + 1;
	if (need > sizeof node_id)
		return ESP_ERR_NO_MEM;
	memcpy(node_id, nid, need);

	size_t der_len = 0;
	err = node_manager_get_key_der(NULL, &der_len);
	if (err != ESP_OK)
		return err;
	uint8_t *der = (uint8_t *)malloc(der_len);
	if (!der)
		return ESP_ERR_NO_MEM;
	err = node_manager_get_key_der(der, &der_len);
	if (err != ESP_OK)
	{
		nm_secure_free(der, der_len);
		return err;
	}

	err = s_nm.sign_cb(node_id, der, der_len, data, data_len, signature_out, sig_len_inout);
	nm_secure_free(der, der_len);
	return err;
}

esp_err_t node_manager_store_cert_der(const uint8_t *cert_der, size_t cert_der_len)
{
	if (!cert_der || cert_der_len == 0)
		return ESP_ERR_INVALID_ARG;
	if (s_nm.nvs == 0)
		return ESP_ERR_INVALID_STATE;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	esp_err_t err = nm_store_blob(NM_NVS_KEY_CERT, cert_der, cert_der_len);
	nm_nvs_unlock();
	if (err == ESP_OK)
	{
		nm_emit_event(NM_EVENT_CERT_STORED);
	}
	return err;
}

esp_err_t node_manager_has_cert(bool *has_cert_out)
{
	if (!has_cert_out)
		return ESP_ERR_INVALID_ARG;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	*has_cert_out = nm_blob_exists(s_nm.nvs, NM_NVS_KEY_CERT);
	nm_nvs_unlock();
	return ESP_OK;
}

static esp_err_t nm_pack_ca_list_blob(const unsigned char **list, const size_t *lens, size_t count, uint8_t **out, size_t *out_len)
{
	if (!list || !lens || count == 0 || !out || !out_len)
		return ESP_ERR_INVALID_ARG;
	// Compute packed length: 4 bytes count + sum(4 + len)
	size_t total = 4;
	for (size_t i = 0; i < count; ++i)
	{
		if (!list[i] || lens[i] == 0)
			return ESP_ERR_INVALID_ARG;
		total += 4 + lens[i];
	}
	uint8_t *buf = (uint8_t *)malloc(total);
	if (!buf)
		return ESP_ERR_NO_MEM;
	// Little-endian u32 header and lengths
	nm_put_u32_le(buf, (uint32_t)count);
	size_t off = 4;
	for (size_t i = 0; i < count; ++i)
	{
		nm_put_u32_le(buf + off, (uint32_t)lens[i]);
		off += 4;
		memcpy(buf + off, list[i], lens[i]);
		off += lens[i];
	}
	*out = buf;
	*out_len = total;
	return ESP_OK;
}

esp_err_t node_manager_set_ca_list_der(const unsigned char **ca_der_list, const size_t *ca_der_lens, size_t ca_count)
{
	if (!ca_der_list || !ca_der_lens || ca_count == 0)
		return ESP_ERR_INVALID_ARG;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	uint8_t *packed = NULL;
	size_t packed_len = 0;
	esp_err_t err = nm_pack_ca_list_blob(ca_der_list, ca_der_lens, ca_count, &packed, &packed_len);
	if (err != ESP_OK)
		return err;
	nm_nvs_lock();
	err = nm_store_blob(NM_NVS_KEY_CA_LIST, packed, packed_len);
	nm_nvs_unlock();
	free(packed);
	if (err == ESP_OK)
		nm_emit_event(NM_EVENT_CA_BUNDLE_UPDATED);
	return err;
}

esp_err_t node_manager_has_ca_list(bool *has_ca_out)
{
	if (!has_ca_out)
		return ESP_ERR_INVALID_ARG;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	*has_ca_out = nm_blob_exists(s_nm.nvs, NM_NVS_KEY_CA_LIST);
	nm_nvs_unlock();
	return ESP_OK;
}

static esp_err_t nm_load_ca_list_packed(uint8_t **blob_out, size_t *len_out)
{
	if (!blob_out || !len_out)
		return ESP_ERR_INVALID_ARG;
	*blob_out = NULL;
	*len_out = 0;
	size_t len = 0;
	nm_nvs_lock();
	esp_err_t err = nm_read_blob_len(s_nm.nvs, NM_NVS_KEY_CA_LIST, &len);
	if (err != ESP_OK)
	{
		nm_nvs_unlock();
		return err;
	}
	if (len == 0)
	{
		nm_nvs_unlock();
		return ESP_ERR_NOT_FOUND;
	}
	uint8_t *buf = (uint8_t *)malloc(len);
	if (!buf)
	{
		nm_nvs_unlock();
		return ESP_ERR_NO_MEM;
	}
	err = nvs_get_blob(s_nm.nvs, NM_NVS_KEY_CA_LIST, buf, &len);
	nm_nvs_unlock();
	if (err != ESP_OK)
	{
		free(buf);
		return err;
	}
	*blob_out = buf;
	*len_out = len;
	return ESP_OK;
}

esp_err_t node_manager_set_signed_config(const uint8_t *cbor_data, size_t cbor_len,
										 const uint8_t *signature, size_t sig_len)
{
	if (!cbor_data || cbor_len == 0 || !signature || sig_len == 0)
		return ESP_ERR_INVALID_ARG;
	if (!s_nm.verify_cb)
		return ESP_ERR_INVALID_STATE;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;

	// Load CA list packed blob
	uint8_t *blob = NULL;
	size_t blob_len = 0;
	esp_err_t err = nm_load_ca_list_packed(&blob, &blob_len);
	if (err != ESP_OK)
		return err;

	// Walk packed blob to build arrays of pointers for callback
	if (blob_len < 4)
	{
		free(blob);
		return ESP_ERR_INVALID_SIZE;
	}
	uint32_t count = (uint32_t)blob[0] | ((uint32_t)blob[1] << 8) | ((uint32_t)blob[2] << 16) | ((uint32_t)blob[3] << 24);
	const unsigned char **list = (const unsigned char **)malloc(sizeof(*list) * count);
	size_t *lens = (size_t *)malloc(sizeof(*lens) * count);
	if (!list || !lens)
	{
		free(list);
		free(lens);
		free(blob);
		return ESP_ERR_NO_MEM;
	}
	size_t off = 4;
	for (uint32_t i = 0; i < count; ++i)
	{
		if (off + 4 > blob_len)
		{
			free(list);
			free(lens);
			free(blob);
			return ESP_ERR_INVALID_SIZE;
		}
		uint32_t l = (uint32_t)blob[off] | ((uint32_t)blob[off + 1] << 8) | ((uint32_t)blob[off + 2] << 16) | ((uint32_t)blob[off + 3] << 24);
		off += 4;
		if (off + l > blob_len)
		{
			free(list);
			free(lens);
			free(blob);
			return ESP_ERR_INVALID_SIZE;
		}
		list[i] = (const unsigned char *)(blob + off);
		lens[i] = (size_t)l;
		off += l;
	}

	// Verify signature
	err = s_nm.verify_cb(cbor_data, cbor_len, signature, sig_len, list, lens, count);
	free(list);
	free(lens);
	free(blob);
	if (err != ESP_OK)
		return err;

	// Store config
	nm_nvs_lock();
	err = nm_store_blob(NM_NVS_KEY_CONFIG, cbor_data, cbor_len);
	nm_nvs_unlock();
	if (err == ESP_OK)
	{
		nm_emit_event(NM_EVENT_CONFIG_UPDATED);
	}
	return err;
}

esp_err_t node_manager_get_config(uint8_t *cbor_out, size_t *cbor_len_inout)
{
	if (!cbor_len_inout)
		return ESP_ERR_INVALID_ARG;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	size_t needed = 0;
	esp_err_t err = nm_read_blob_len(s_nm.nvs, NM_NVS_KEY_CONFIG, &needed);
	if (err != ESP_OK)
	{
		nm_nvs_unlock();
		return err;
	}
	if (needed == 0)
	{
		nm_nvs_unlock();
		return ESP_ERR_NOT_FOUND;
	}
	if (!cbor_out)
	{ // caller querying length
		*cbor_len_inout = needed;
		nm_nvs_unlock();
		return ESP_OK;
	}
	if (*cbor_len_inout < needed)
	{
		*cbor_len_inout = needed;
		nm_nvs_unlock();
		return ESP_ERR_NO_MEM;
	}
	err = nvs_get_blob(s_nm.nvs, NM_NVS_KEY_CONFIG, cbor_out, cbor_len_inout);
	nm_nvs_unlock();
	return err;
}

esp_err_t node_manager_clear_config(void)
{
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	esp_err_t err = nvs_erase_key(s_nm.nvs, NM_NVS_KEY_CONFIG);
	if (err == ESP_ERR_NVS_NOT_FOUND)
	{
		nm_nvs_unlock();
		return ESP_OK;
	}
	if (err != ESP_OK)
	{
		nm_nvs_unlock();
		return err;
	}
	err = nvs_commit(s_nm.nvs);
	nm_nvs_unlock();
	return err;
}

esp_err_t node_manager_set_config_unverified(const uint8_t *cbor_data, size_t cbor_len)
{
	if (!cbor_data || cbor_len == 0)
		return ESP_ERR_INVALID_ARG;
	if (s_nm.nvs == 0)
		return ESP_ERR_INVALID_STATE;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	esp_err_t err = nm_store_blob(NM_NVS_KEY_CONFIG, cbor_data, cbor_len);
	nm_nvs_unlock();
	if (err == ESP_OK)
		nm_emit_event(NM_EVENT_CONFIG_UPDATED);
	return err;
}

esp_err_t node_manager_has_key(bool *has_key_out)
{
	if (!has_key_out)
		return ESP_ERR_INVALID_ARG;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	*has_key_out = nm_blob_exists(s_nm.nvs, NM_NVS_KEY_PRIVKEY);
	nm_nvs_unlock();
	return ESP_OK;
}

esp_err_t node_manager_set_key_der(const uint8_t *der, size_t der_len)
{
	if (!der || der_len == 0)
		return ESP_ERR_INVALID_ARG;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	esp_err_t err = nm_store_blob(NM_NVS_KEY_PRIVKEY, der, der_len);
	nm_nvs_unlock();
	if (err == ESP_OK)
		nm_emit_event(NM_EVENT_KEY_STORED);
	return err;
}

esp_err_t node_manager_get_key_der(uint8_t *der_out, size_t *der_len_inout)
{
	if (!der_len_inout)
		return ESP_ERR_INVALID_ARG;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	size_t needed = 0;
	esp_err_t err = nm_read_blob_len(s_nm.nvs, NM_NVS_KEY_PRIVKEY, &needed);
	if (err != ESP_OK)
	{
		nm_nvs_unlock();
		return err;
	}
	if (needed == 0)
	{
		nm_nvs_unlock();
		return ESP_ERR_NOT_FOUND;
	}
	if (!der_out)
	{
		*der_len_inout = needed;
		nm_nvs_unlock();
		return ESP_OK;
	}
	if (*der_len_inout < needed)
	{
		*der_len_inout = needed;
		nm_nvs_unlock();
		return ESP_ERR_NO_MEM;
	}
	err = nvs_get_blob(s_nm.nvs, NM_NVS_KEY_PRIVKEY, der_out, der_len_inout);
	nm_nvs_unlock();
	return err;
}

esp_err_t node_manager_reset_key_and_regen(void)
{
	if (s_nm.nvs == 0)
		return ESP_ERR_INVALID_STATE;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	// Erase existing key
	nm_nvs_lock();
	esp_err_t err = nvs_erase_key(s_nm.nvs, NM_NVS_KEY_PRIVKEY);
	if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND)
	{
		nm_nvs_unlock();
		return err;
	}
	err = nvs_commit(s_nm.nvs);
	nm_nvs_unlock();
	if (err != ESP_OK)
		return err;

	nm_emit_event(NM_EVENT_NO_KEY);

	if (!s_nm.keygen_cb)
	{
		// No generator; just signal that a CSR is available if a key appears later
		if (s_nm.csr_cb)
			nm_emit_event(NM_EVENT_CSR_AVAILABLE);
		return ESP_OK;
	}

	// Generate new key
	uint8_t buf[2048];
	size_t len = sizeof(buf);
	err = s_nm.keygen_cb(buf, &len);
	if (err != ESP_OK)
	{
		nm_secure_memzero(buf, sizeof(buf));
		return err;
	}
	if (len > 0)
	{
		nm_nvs_lock();
		esp_err_t serr = nm_store_blob(NM_NVS_KEY_PRIVKEY, buf, len);
		nm_nvs_unlock();
		nm_secure_memzero(buf, len);
		if (serr != ESP_OK)
			return serr;
		nm_emit_event(NM_EVENT_KEY_STORED);
	}
	else
	{
		nm_secure_memzero(buf, sizeof(buf));
	}

	// After key regeneration, cert is no longer valid; prompt reprovision
	nm_emit_event(NM_EVENT_NO_CERT);
	if (s_nm.csr_cb)
		nm_emit_event(NM_EVENT_CSR_AVAILABLE);
	return ESP_OK;
}

esp_err_t node_manager_clear_certs(void)
{
	if (s_nm.nvs == 0)
		return ESP_ERR_INVALID_STATE;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	// Erase cert and CA bundle
	nm_nvs_lock();
	esp_err_t e1 = nvs_erase_key(s_nm.nvs, NM_NVS_KEY_CERT);
	if (e1 != ESP_OK && e1 != ESP_ERR_NVS_NOT_FOUND)
	{
		nm_nvs_unlock();
		return e1;
	}
	esp_err_t e2 = nvs_erase_key(s_nm.nvs, NM_NVS_KEY_CA_LIST);
	if (e2 != ESP_OK && e2 != ESP_ERR_NVS_NOT_FOUND)
	{
		nm_nvs_unlock();
		return e2;
	}
	esp_err_t err = nvs_commit(s_nm.nvs);
	nm_nvs_unlock();
	if (err != ESP_OK)
		return err;

	nm_emit_event(NM_EVENT_NO_CERT);
	nm_emit_event(NM_EVENT_CA_BUNDLE_UPDATED);
	if (s_nm.csr_cb)
		nm_emit_event(NM_EVENT_CSR_AVAILABLE);
	return ESP_OK;
}

esp_err_t node_manager_get_cert_der(uint8_t *cert_out, size_t *cert_len_inout)
{
	if (!cert_len_inout)
		return ESP_ERR_INVALID_ARG;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	size_t needed = 0;
	esp_err_t err = nm_read_blob_len(s_nm.nvs, NM_NVS_KEY_CERT, &needed);
	if (err != ESP_OK)
	{
		nm_nvs_unlock();
		return err;
	}
	if (needed == 0)
	{
		nm_nvs_unlock();
		return ESP_ERR_NOT_FOUND;
	}
	if (!cert_out)
	{
		*cert_len_inout = needed;
		nm_nvs_unlock();
		return ESP_OK;
	}
	if (*cert_len_inout < needed)
	{
		*cert_len_inout = needed;
		nm_nvs_unlock();
		return ESP_ERR_NO_MEM;
	}
	err = nvs_get_blob(s_nm.nvs, NM_NVS_KEY_CERT, cert_out, cert_len_inout);
	nm_nvs_unlock();
	return err;
}

esp_err_t node_manager_get_ca_list_der_packed(uint8_t *out, size_t *len_inout)
{
	if (!len_inout)
		return ESP_ERR_INVALID_ARG;
	esp_err_t werr = nm_wait_ready_blocking();
	if (werr != ESP_OK)
		return werr;
	nm_nvs_lock();
	size_t needed = 0;
	esp_err_t err = nm_read_blob_len(s_nm.nvs, NM_NVS_KEY_CA_LIST, &needed);
	if (err != ESP_OK)
	{
		nm_nvs_unlock();
		return err;
	}
	if (needed == 0)
	{
		nm_nvs_unlock();
		return ESP_ERR_NOT_FOUND;
	}
	if (!out)
	{
		*len_inout = needed;
		nm_nvs_unlock();
		return ESP_OK;
	}
	if (*len_inout < needed)
	{
		*len_inout = needed;
		nm_nvs_unlock();
		return ESP_ERR_NO_MEM;
	}
	err = nvs_get_blob(s_nm.nvs, NM_NVS_KEY_CA_LIST, out, len_inout);
	nm_nvs_unlock();
	return err;
}
