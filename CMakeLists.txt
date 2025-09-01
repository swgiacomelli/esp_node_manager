idf_component_register(
    SRCS "node_manager.c"
    INCLUDE_DIRS "include"
    REQUIRES 
    nvs_flash 
    esp_event
)
