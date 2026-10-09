final: prev: {
  curl = prev.curl.override { http3Support = true; };
}
