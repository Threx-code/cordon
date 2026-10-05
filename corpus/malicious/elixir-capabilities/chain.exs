packed = Base.decode64!(blob)
code = :zlib.gunzip(packed)
Code.eval_string(code)
