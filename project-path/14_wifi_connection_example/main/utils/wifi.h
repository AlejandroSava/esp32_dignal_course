#ifndef WIFI_H
#define WIFI_H

#include <stddef.h>   
#include <stdint.h>   


// ======= CHANGE THESE =======
#define WIFI_SSID "INFINITUM2.0_2.4"
#define WIFI_PASS "8765171390"
#define WIFI_MAX_RETRY 10
// ============================


void wifi_init_sta(void);

void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data);

#endif 
