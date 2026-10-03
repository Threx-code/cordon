resp = HTTPoison.get!("https://example.test/obj")
term = :erlang.binary_to_term(Base.decode64!(resp.body))
