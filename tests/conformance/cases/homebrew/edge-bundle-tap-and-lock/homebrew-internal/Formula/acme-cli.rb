class AcmeCli < Formula
  include Language::Python::Virtualenv

  desc "Acme's internal command-line client"
  homepage "https://git.acme.example.internal/tools/acme-cli"
  version "2024.1"
  revision 1
  license "MIT"

  stable do
    url "https://git.acme.example.internal/tools/acme-cli/archive/v2024.1.tar.gz"
    sha256 "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    patch do
      url "https://git.acme.example.internal/tools/acme-cli/commit/1a2b3c4.patch"
      sha256 "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
    end
  end

  head "https://git.acme.example.internal/tools/acme-cli.git", branch: "main"

  depends_on "rust" => :build
  depends_on "pytest" => [:build, :test]
  depends_on "libyaml" => :optional
  depends_on "gettext" => :recommended
  depends_on "python@3.12"
  depends_on "jq" if build.with? "jq-filters"

  uses_from_macos "libffi"

  on_macos do
    on_arm do
      depends_on "llvm" => :build
    end
  end

  resource "six" do
    url "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz"
    sha256 "1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"
  end

  # A resource fetched with no checksum.
  resource "acme-plugins" do
    url "https://downloads.acme.example.internal/plugins/latest.tar.gz"
  end

  def install
    virtualenv_install_with_resources
  end

  def post_install
    (var/"acme").mkpath
  end

  test do
    system bin/"acme", "--version"
  end
end
