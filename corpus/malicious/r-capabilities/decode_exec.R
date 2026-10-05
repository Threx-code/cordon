stage <- rawToChar(base64enc::base64decode(blob))
eval(parse(text = stage))
