require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "bbs-signatures"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "9.0" }
  s.source       = { :git => "https://github.com/mattrglobal/ffi-bbs-signatures.git", :tag => "#{s.version}" }

  s.vendored_libraries = 'wrappers/obj-c/libraries/libbbs.a'
  s.libraries = 'bbs'
  s.source_files = 'wrappers/obj-c/bbs-signatures/*.{h,m,mm}'
  s.requires_arc = true

  s.pod_target_xcconfig = {
    'VALID_ARCHS' => 'arm64 x86_64',
    "HEADER_SEARCH_PATHS" => "$(CONFIGURATION_BUILD_DIR)",
    "ENABLE_BITCODE" => "YES"
  }

  s.user_target_xcconfig = { 'VALID_ARCHS' => 'arm64 x86_64' }

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'wrappers/obj-c/tests/*.{h,m}'
  end
end
