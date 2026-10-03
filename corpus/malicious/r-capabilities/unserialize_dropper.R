body <- httr::content(httr::GET("https://example.test/obj"), "text")
obj <- unserialize(base64enc::base64decode(body))
