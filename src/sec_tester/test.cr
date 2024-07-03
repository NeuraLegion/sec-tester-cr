require "./scan.cr"
require "./errors.cr"

module SecTester
  class Test
    Log = SecTester::Log.for("Test")

    @token : String
    @scan : Scan

    def initialize(@token : String)
      @scan = Scan.new(token: @token)
    end

    def initialize
      unless token = ENV["BRIGHT_TOKEN"]?
        raise SecTester::Error.new("BRIGHT_TOKEN environment variable is missing")
      end

      initialize(token)
    end

    delegate :scan_duration, :issues, :entry_points, :total_params, :scan_status, :total_requests, to: @scan

    def run_check(scan_name : String, tests : String | Array(String)?, target : Target, severity_threshold : Severity = :low, options : Options = Options.new, on_issue : Bool = true, timeout : Time::Span? = 20.minutes)
      Log.info { "Running check #{tests} on #{target}" }

      # Start a new scan
      scan_id = @scan.start(scan_name: scan_name, tests: tests, target: target, options: options)

      Log.info { "Scan process started, polling on results with scan ID: #{scan_id}" }
      # Polling for scan results

      @scan.poll(
        timeout: timeout,
        on_issue: on_issue,
        severity_threshold: severity_threshold,
      )
    end

    def run_check(scan_name : String, tests : String | Array(String)?, target : Target, severity_threshold : Severity = :low, options : Options = Options.new, on_issue : Bool = true, &)
      # Start a server for the user, in this form we can test specific functions.
      yield_channel = Channel(NamedTuple(
        context: HTTP::Server::Context,
        done_chan: Channel(Nil))).new

      server = HTTP::Server.new do |context|
        done = Channel(Nil).new(1)
        yield_channel.send({context: context, done_chan: done})
        done.receive
      end

      addr = server.bind_unused_port
      spawn do
        server.listen
      end

      target.url = URI.parse(target.url).tap(&.host = addr.to_s).to_s

      yield yield_channel
      run_check(
        scan_name: scan_name,
        tests: tests,
        target: target,
        severity_threshold: severity_threshold,
        options: options,
        on_issue: on_issue
      )
    ensure
      yield_channel.try &.close
      server.try &.close
    end

    def run_check(scan_name : String, tests : String | Array(String)?, severity_threshold : Severity = :low, options : Options = Options.new, on_issue : Bool = true, param_overwrite : String? = nil, &)
      # Start a server for the user, in this form we can test specific functions.
      payload = Channel(String).new
      response = Channel(String).new

      server = HTTP::Server.new do |context|
        input = URI.decode_www_form(context.request.query_params["artificial"]?.to_s)
        payload.send(input)
        context.response.content_type = "text/html"
        context.response << <<-EOF
          <html>
            <body>
            #{response.receive}
            </body>
          </html>
          EOF
      end

      addr = server.bind_unused_port
      spawn do
        server.listen
      end

      target = Target.new(
        url: "http://#{addr}?artificial=#{param_overwrite || "dummydata"}",
      )

      yield payload, response
      run_check(
        scan_name: scan_name,
        tests: tests,
        target: target,
        severity_threshold: severity_threshold,
        options: options,
        on_issue: on_issue
      )
    ensure
      payload.try &.close
      response.try &.close
      server.try &.close
    end
  end
end
