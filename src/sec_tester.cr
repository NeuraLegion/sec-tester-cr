require "log"
require "./sec_tester/target.cr"
require "./sec_tester/issue.cr"
require "./sec_tester/tests.cr"
require "./sec_tester/options.cr"
require "./sec_tester/test.cr"
require "./sec_tester/severity.cr"

module SecTester
  Log     = ::Log.for("SecTester")
  VERSION = "1.5.2"

  backend = ::Log::IOBackend.new(STDOUT)

  ::Log.setup do |c|
    c.bind("SecTester.*", ::Log::Severity::Error, backend)
  end

  # Not the most beautiful way to do this, but it works.
  class Error < Exception; end

  class IssueFound < Exception; end

  class Timeout < Exception; end

  # Check if the nexploit-cli is available, if not raise an error.
  {% system("command -v nexploit-cli") %} # ⚠️ nexploit-cli not found. Please install it using: npm install -g @neuralegion/nexploit-cli ⚠️
end
