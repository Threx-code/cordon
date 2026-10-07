class AcmeSync < Formula
  desc "Sync tool, Acme's own"
  homepage "https://git.acme.example.internal/tools/acme-sync"
  url "https://git.acme.example.internal/tools/acme-sync/archive/v3.2.0.tar.gz"
  sha256 "3c59dc048e8850243be8079a5c74d079f3a1f35bd7aeb4ebc3e1b0e3d4c5b6a7"

  depends_on "cmake" => :build
  depends_on "libgit2"

  def install
    system "cmake", "-S", ".", "-B", "build", *std_cmake_args
    system "cmake", "--install", "build"
  end
end
