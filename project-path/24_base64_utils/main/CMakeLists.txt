idf_component_register(
                    SRCS
                        "24_base64_utils.c"
                        "./utils/base64.c"
                        "./utils/http_transactions.c"
                        "./utils/wifi.c"

                    INCLUDE_DIRS
                        "."
                        "./utils"
)
