#include <string.h>
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "node_manager.h"

static const char *TAG = "nm_example";

static esp_err_t example_get_node_id(char **out, size_t *len) {
    static char nid[] = "example-node";
    *out = nid;
    *len = strlen(nid);
    return ESP_OK;
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    node_manager_init_config_t cfg = {
        .get_node_id_cb = example_get_node_id,
        .keygen_cb = NULL,
        .sign_cb = NULL,
        .csr_cb = NULL,
        .verify_cb = NULL,
        .post_event_cb = NULL,
        .nvs_namespace = NULL
    };
    esp_err_t err = node_manager_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "node_manager_init failed: %d", err);
    } else {
        ESP_LOGI(TAG, "node_manager initialized, version %s", NODE_MANAGER_VERSION_STRING);
    }
}
