require "log"

require "./sec_tester/target.cr"
require "./sec_tester/issue.cr"
require "./sec_tester/tests.cr"
require "./sec_tester/options.cr"
require "./sec_tester/test.cr"
require "./sec_tester/severity.cr"
require "./sec_tester/repeater.cr"

module SecTester
  Log     = ::Log.for("SecTester")
  VERSION = "1.6.7"

  backend = ::Log::IOBackend.new(STDOUT)

  ::Log.setup do |c|
    c.bind("SecTester.*", ::Log::Severity::Error, backend)
  end
end
