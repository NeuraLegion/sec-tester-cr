require "./spec_helper"
require "http"
require "uri"
require "har"

describe SecTester::Target do
  it "should be able to create a new target" do
    target = SecTester::Target.new("http://www.google.com")
    target.url.should eq("http://www.google.com")
    target.method.should eq("GET")
  end

  it "generate proper HAR file" do
    target = SecTester::Target.new("http://www.google.com")
    har = HAR.from_string(target.to_har)
    har.entries.size.should eq(1)
    har.entries.first.request.url.should eq("http://www.google.com")
    har.entries.first.request.method.should eq("GET")
  end

  it "raises on faulty scheme" do
    expect_raises(SecTester::Error) do
      target = SecTester::Target.new("www.google.com")
    end
  end

  it "raises on missing host" do
    expect_raises(SecTester::Error) do
      target = SecTester::Target.new("http://")
    end
  end
end

describe SecTester::Test do
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
    expect_raises(SecTester::IssueFound) do
      tester.run_check(
        scan_name: "UnitTestingScan - XSS",
        tests: "xss",
        target: SecTester::Target.new(
          method: "GET",
          url: "http://#{addr}/?name=jhon",
          response_headers: HTTP::Headers{"Content-Type" => "text/html"}
        )
      )
    end
  ensure
    server.try &.close
    tester.try &.cleanup
  end

  it "starts a new scan for XSS and OSI" do
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
    expect_raises(SecTester::IssueFound) do
      tester.run_check(
        scan_name: "UnitTestingScan - XSS + OSI",
        tests: ["xss", "osi"],
        target: SecTester::Target.new(
          url: "http://#{addr}/?name=jhon",
        )
      )
    end
  ensure
    server.try &.close
    tester.try &.cleanup
  end
end
