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
      SecTester::Target.new("www.google.com")
    end
  end

  it "raises on missing host" do
    expect_raises(SecTester::Error) do
      SecTester::Target.new("http://")
    end
  end

  it "raises on wrong method" do
    expect_raises(SecTester::Error) do
      SecTester::Target.new(
        method: "blabla",
        url: "http://www.google.com"
      )
    end
  end
end

describe SecTester::Options do
  it "Sets defaults for all options" do
    options = SecTester::Options.new
    options.smart_scan?.should eq(true)
  end

  it "Raise on wrong location" do
    expect_raises(SecTester::Error) do
      SecTester::Options.new(param_locations: ["blabla"])
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
        ),
        options: SecTester::Options.new(
          project_id: "7Yx6ovyMj954WHcLvYyWzo",
        )
      )
    end
  ensure
    server.try &.close
  end

  it "starts a new scan for cookies" do
    server = HTTP::Server.new do |context|
      context.response.headers["Set-Cookie"] = "foo=bar"
    end

    addr = server.bind_unused_port
    spawn do
      server.listen
    end

    tester = SecTester::Test.new
    expect_raises(SecTester::IssueFound) do
      tester.run_check(
        scan_name: "UnitTestingScan - cookie_security",
        tests: ["cookie_security"],
        target: SecTester::Target.new(
          url: "http://#{addr}/",
        ),
        options: SecTester::Options.new(
          project_id: "7Yx6ovyMj954WHcLvYyWzo",
        )
      )
    end
  ensure
    server.try &.close
  end

  it "starts a new scan for cookies - Skip low" do
    server = HTTP::Server.new do |context|
      context.response.headers["Set-Cookie"] = "foo=bar"
    end

    addr = server.bind_unused_port
    spawn do
      server.listen
    end

    tester = SecTester::Test.new

    tester.run_check(
      scan_name: "UnitTestingScan - cookie_security - Skip low",
      tests: ["cookie_security"],
      target: SecTester::Target.new(
        url: "http://#{addr}/",
      ),
      severity_threshold: :medium,
      options: SecTester::Options.new(
        project_id: "7Yx6ovyMj954WHcLvYyWzo",
      ),
    )
  ensure
    server.try &.close
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
        ),
        options: SecTester::Options.new(
          project_id: "7Yx6ovyMj954WHcLvYyWzo",
        )
      )
    end
  ensure
    server.try &.close
  end

  it "starts a new scan with options" do
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
        scan_name: "UnitTestingScan - options",
        tests: ["xss", "osi"],
        target: SecTester::Target.new(
          url: "http://#{addr}/?name=jhon",
        ),
        options: SecTester::Options.new(
          smart_scan: false,
          skip_static_parameters: false,
          project_id: "7Yx6ovyMj954WHcLvYyWzo",
        )
      )
    end
    (tester.scan_duration > 0.seconds).should be_true
  ensure
    server.try &.close
  end

  it "starts SQLi test via repeater" do
    server = HTTP::Server.new do |context|
      name = URI.decode_www_form(context.request.query_params["name"]?.to_s)

      context.response.content_type = "text/html"
      context.response << <<-EOF
        <html>
          <body>
            <h1>Hello, world!</h1>
            <p>#{name}</p>
            SQL Error: you have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'jhon'' at line 1
            PostgreSQL Error: ERROR: syntax error at or near "jhon"
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
        scan_name: "UnitTestingScan - sqli testing",
        tests: ["sqli"],
        target: SecTester::Target.new(
          url: "http://#{addr}/?name=jhon",
        ),
        options: SecTester::Options.new(
          smart_scan: false,
          skip_static_parameters: false,
          project_id: "7Yx6ovyMj954WHcLvYyWzo",
        )
      )
    end
    (tester.scan_duration > 0.seconds).should be_true
  ensure
    server.try &.close
  end

  it "starts a function oriented test for XSS" do
    tester = SecTester::Test.new
    expect_raises(SecTester::IssueFound) do
      tester.run_check(scan_name: "UnitTestingScan - XSS - function only", tests: ["xss"]) do |payload, response|
        spawn do
          while payload_data = payload.receive?
            # This is where we send the payload to the function and send back a response
            # In this example we just want to send back the payload
            # as we are testing reflection
            # my_function is a demo function that returns the payload
            response_data = my_function(payload_data)

            # we end up sending the response back to the channel
            response.send(response_data)
          end
        end
      end
    end
  end

  it "starts a function oriented test for XSS including param_overwrite" do
    tester = SecTester::Test.new
    expect_raises(SecTester::IssueFound) do
      tester.run_check(scan_name: "xss", tests: ["xss"], param_overwrite: "abcdefu") do |payload, response|
        spawn do
          while payload_data = payload.receive?
            # This is where we send the payload to the function and send back a response
            # In this example we just want to send back the payload
            # as we are testing reflection
            # my_function is a demo function that returns the payload
            response_data = my_function(payload_data)

            # we end up sending the response back to the channel
            response.send(response_data)
          end
        end
      end
    end
  end

  it "starts a request/response oriented test for XSS" do
    tester = SecTester::Test.new
    target = SecTester::Target.new(
      url: "http://localhost?id=5"
    )
    expect_raises(SecTester::IssueFound) do
      tester.run_check(scan_name: "UnitTestingScan - XSS - request/response test", target: target, tests: ["xss"]) do |context_channel|
        spawn do
          while context_tuple = context_channel.receive?
            context = context_tuple[:context]
            done_channel = context_tuple[:done_chan]
            input = context.request.query_params["id"]?.to_s
            response_data = my_function(input)

            context.response.headers["Content-Type"] = "text/html"
            context.response.status_code = 200
            context.response.print(response_data)
            done_channel.send(nil)
          end
        end
      end
    end
  end
end

def my_function(data : String) : String
  data
end
