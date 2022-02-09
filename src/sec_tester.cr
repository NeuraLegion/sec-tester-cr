require "log"
require "./process_handler.cr"
require "./target.cr"
require "./test.cr"

module SecTester
  Log     = ::Log.for("SecTester")
  VERSION = "1.1.0"

  backend = ::Log::IOBackend.new(STDOUT)

  ::Log.setup do |c|
    c.bind("SecTester.*", ::Log::Severity::Debug, backend)
  end

  # Not the most beautiful way to do this, but it works.
  class Error < Exception; end

  class IssueFound < Exception; end

  class Timeout < Exception; end
end
