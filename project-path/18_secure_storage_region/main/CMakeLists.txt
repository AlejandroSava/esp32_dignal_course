idf_component_register(SRCS 
                        
                        "./utils/aes_cbc.c"
                        "./utils/hmac_sha512.c"
                        "./utils/pkcs_7.c"
                        "./utils/secure_storage_nvs.c"
                        "./utils/wake_stub.c"
                        "./utils/api_secure_storage.c"
                        "18_secure_storage_region.c"

                    INCLUDE_DIRS 
                        "."
                        "./utils")
