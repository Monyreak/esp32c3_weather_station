/* HTTPS GET Example using plain mbedTLS sockets
 *
 * Contacts the howsmyssl.com API via TLS v1.2 and reads a JSON
 * response.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * SPDX-FileCopyrightText: The Mbed TLS Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * SPDX-FileContributor: 2015-2021 Espressif Systems (Shanghai) CO LTD
 */
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "esp_netif.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
#include "psa/crypto.h"
#endif
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "driver/i2c.h"





#define I2C_SCL_PIN 8 
#define I2C_SDA_PIN 10
#define I2C_PORT I2C_NUM_0
#define I2FREQ_HZ 100000
#define SHTC3_ADDRESS 0x70

/* Constants that aren't configurable in menuconfig */
#define WEB_SERVER "www.wttr.in"
#define WEB_PORT "443"
#define WEB_URL "https://www.wttr.in/"
#define PATH "/Scotts+Valley?format=%l:+%t+%h"

#define SERVER_URL_MAX_SZ 256

static const char *TAG = "example";
#define TIME_PERIOD (86400000000ULL)


static const char *REQUEST = "GET " PATH " HTTP/1.1\r\n"
    "Host: "WEB_SERVER"\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
    "\r\n";

void combine_weather_data(char *combined_data, size_t combined_size, 
                          const char *indoor_data, const char *outdoor_data) {
    snprintf(combined_data, combined_size, "%s, %s", indoor_data, outdoor_data);
}


static void https_get_task(void *pvParameters)
{
    char buf[512];
    int ret, flags, len;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to initialize PSA crypto, returned %d", (int) status);
        return;
    }
#endif

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Attaching the certificate bundle...");

    ret = esp_crt_bundle_attach(&conf);

    if(ret < 0)
    {
        ESP_LOGE(TAG, "esp_crt_bundle_attach returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x", -ret);
        goto exit;
    }

    while(1) {
        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        }
        else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));

        ESP_LOGI(TAG, "Writing HTTP request...");

        size_t written_bytes = 0;
        do {
            ret = mbedtls_ssl_write(&ssl,
                                    (const unsigned char *)REQUEST + written_bytes,
                                    strlen(REQUEST) - written_bytes);
            if (ret >= 0) {
                ESP_LOGI(TAG, "%d bytes written", ret);
                written_bytes += ret;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
                ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
                goto exit;
            }
        } while(written_bytes < strlen(REQUEST));

        ESP_LOGI(TAG, "Reading HTTP response...");

        do
        {
            len = sizeof(buf) - 1;
            bzero(buf, sizeof(buf));
            ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

#if CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 && CONFIG_MBEDTLS_CLIENT_SSL_SESSION_TICKETS
            if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
                ESP_LOGD(TAG, "got session ticket in TLS 1.3 connection, retry read");
                continue;
            }
#endif // CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 && CONFIG_MBEDTLS_CLIENT_SSL_SESSION_TICKETS

            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }

            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ret = 0;
                break;
            }

            if (ret < 0) {
                ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
                break;
            }

            if (ret == 0) {
                ESP_LOGI(TAG, "connection closed");
                break;
            }

            len = ret;
            ESP_LOGD(TAG, "%d bytes read", len);
            /* Print response directly to stdout as it is read */
            for (int i = 0; i < len; i++) {
                putchar(buf[i]);
            }
        } while(1);

        mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if (ret != 0) {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }

        putchar('\n'); // JSON output doesn't have a newline at end

        static int request_count;
        ESP_LOGI(TAG, "Completed %d requests", ++request_count);
        printf("Minimum free heap size: %" PRIu32 " bytes\n", esp_get_minimum_free_heap_size());

        for (int countdown = 10; countdown >= 0; countdown--) {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
    }
}
float parse_temperature(uint8_t *data) {
    uint16_t temp_data = (data[0] << 8) | data[1];
    return -45.0 + 175.0 * ((float)temp_data / 65535.0);
}

float parse_humidity(uint8_t *data) {
    uint16_t humid_data = (data[3] << 8) | data[4];
    return 100.0 * ((float)humid_data / 65535.0);
}

void i2c_init() {
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = I2C_SDA_PIN,
        .sda_pullup_en = GPIO_PULLUP_DISABLE,
        .scl_io_num = I2C_SCL_PIN,
        .scl_pullup_en = GPIO_PULLUP_DISABLE,
        .master.clk_speed = I2FREQ_HZ
    };

    i2c_param_config(I2C_PORT, &conf);
    i2c_driver_install(I2C_PORT, conf.mode, 0, 0, 0);
}

void i2c_read_data(uint8_t *data) {
    uint8_t cmd_input[2] = {0x7C, 0xA2};
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SHTC3_ADDRESS << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write(cmd, cmd_input, 2, true);
    i2c_master_stop(cmd);
    i2c_master_cmd_begin(I2C_PORT, cmd, 1000 / portTICK_PERIOD_MS);
    i2c_cmd_link_delete(cmd);

    cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SHTC3_ADDRESS << 1) | I2C_MASTER_READ, true);
    i2c_master_read(cmd, data, 6, I2C_MASTER_LAST_NACK);
    i2c_master_stop(cmd);
    i2c_master_cmd_begin(I2C_PORT, cmd, 1000 / portTICK_PERIOD_MS);
    i2c_cmd_link_delete(cmd);
}
void http_post_request(const char *combined_data) {
    esp_http_client_config_t config = {
        .url = "http://192.168.150.245:1234/weather", // Replace with your server's IP and port
        .method = HTTP_METHOD_POST,
        
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    char content_length_header[32];
    snprintf(content_length_header, sizeof(content_length_header), "Content-Length: %d", strlen(combined_data));

    esp_http_client_set_post_field(client, combined_data, strlen(combined_data));
    esp_http_client_set_header(client, "Content-Type", "text/plain");
    esp_http_client_set_header(client, "Content-Length", content_length_header);

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}




void app_main(void) {
    // Initialize NVS
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Configure and start Wi-Fi or Ethernet connection
    ESP_ERROR_CHECK(example_connect());
    char outdoor_weather[256] = {0};
    char combined_data[512] = {0};

    // Initialize I2C
    i2c_init();

    // Create a task for HTTPS GET request
    xTaskCreate(&https_get_task, "https_get_task", 8192, NULL, 5, NULL);

    uint8_t data[6];
    char outdoor_weather_info[256];
    char combined_data[512];
    TickType_t last_weather_fetch = xTaskGetTickCount();

    while (1) {
        // Fetch and post weather data every 30 seconds
        if ((xTaskGetTickCount() - last_weather_fetch) * portTICK_PERIOD_MS >= 30000) {
            http_get_weather_info(outdoor_weather_info, sizeof(outdoor_weather_info));
            last_weather_fetch = xTaskGetTickCount();

            // Read sensor data
            i2c_read_data(data);
            float celcius = parse_temperature(data);
            float fah = celcius * (9.0/5.0) + 32.0;
            float humidity = parse_humidity(data);

            // Prepare and post combined data
            snprintf(combined_data, sizeof(combined_data), "Indoors T:%.2fF, H:%.2f%%, %s", fah, humidity, outdoor_weather_info);
            http_post_request(combined_data);
        }

        // Delay for 2 seconds
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}
