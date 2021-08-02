require "./spec_helper"
require "http"
require "uri"

describe SecTester::Test do
  it "starts a new scan for OSI" do
    server = HTTP::Server.new do |context|
      command = URI.decode_www_form(context.request.query_params["command"]?.to_s)

      context.response.content_type = "text/html"
      context.response << <<-EOF
        <html>
          <body>
            <h1>Hello, world!</h1>
            <p>#{`#{command}`}</p>
          </body>
        </html>
        EOF
    end

    addr = server.bind_unused_port
    spawn do
      server.listen
    end

    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "UnitTestingScan - OSI",
      test_name: "osi",
      target: SecTester::Target.new("http://#{addr}/?command=time")
      )
  ensure
    server.try &.close
    tester.try &.cleanup
  end

  it "starts a new scan for XSS" do
    server = HTTP::Server.new do |context|
      name = URI.decode_www_form(context.request.query_params["name"]?.to_s)

      context.response.content_type = "text/html"
      context.response << <<-EOF
        <html>
          <body>
            <h1>Hello, world!</h1>
            <p>#{name}</p>
          </body>
        </html>
        EOF
    end

    addr = server.bind_unused_port
    spawn do
      server.listen
    end

    tester = SecTester::Test.new
    tester.run_check(
      scan_name: "UnitTestingScan - XSS",
      test_name: "xss",
      target: SecTester::Target.new("http://#{addr}/?name=jhon")
      )
  ensure
    server.try &.close
    tester.try &.cleanup
  end
end
