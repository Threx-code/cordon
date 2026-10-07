cask "acme-app" do
  version :latest
  sha256 :no_check

  url "https://downloads.acme.example.internal/app/AcmeApp.dmg"
  name "Acme App"
  desc "Acme's internal desktop application"
  homepage "https://acme.example.internal/app"

  depends_on formula: "jq"
  depends_on cask: ["firefox", "acme-fonts"]
  depends_on macos: ">= :ventura"

  app "Acme App.app"

  preflight do
    system_command "/usr/bin/true"
  end

  postflight do
    system_command "/usr/bin/true"
  end

  installer script: {
    executable: "Acme App.app/Contents/Resources/setup",
    args:       ["--silent"],
  }
end
