idf_component_register(SRCS 
                        "18_secure_storage_region.c"
                        "./utils/aes_cbc.c"
                        "./utils/hmac_sha512.c"
                        "./utils/pkcs_7.c"
                        "./utils/secure_storage_nvs.c"
                        "./utils/wake_stub.c"

                    INCLUDE_DIRS 
                        "."
                        "./utils")
