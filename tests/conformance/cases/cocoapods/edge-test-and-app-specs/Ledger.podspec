Pod::Spec.new do |s|
  s.name         = 'Ledger'
  s.version      = '2.1.0'
  s.summary      = 'Double-entry bookkeeping for iOS apps.'
  s.homepage     = 'https://example.invalid/ledger'
  s.license      = { :type => 'MIT' }
  s.author       = { 'Ada Example' => 'ada@example.invalid' }
  s.source       = { :git => 'https://example.invalid/ledger.git', :tag => s.version.to_s }
  s.ios.deployment_target = '15.0'
  s.source_files = 'Sources/**/*.swift'

  s.dependency 'Alamofire', '~> 5.9'

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'Tests/**/*.swift'
    test_spec.dependency 'Quick', '~> 7.0'
    test_spec.dependency 'Nimble', '~> 13.0'
  end

  s.app_spec 'Demo' do |app_spec|
    app_spec.source_files = 'Demo/**/*.swift'
    app_spec.dependency 'SnapKit', '~> 5.7'
  end
end
