require "./scan.cr"

module SecTester
  class Test
    Log = SecTester::Log.for("Test")

    @token : String

    @repeater_process : Process
    @scan : Scan

    def initialize(@token : String)
      @scan = Scan.new(token: @token)
      @repeater_process = start_repeater
      wait_for_repeater
      raise SecTester::Error.new("Repeater process isn't running: #{repeater_output}") unless @repeater_process.exists?
    end

    def initialize
      unless token = ENV["NEXPLOIT_TOKEN"]?
        raise SecTester::Error.new("NEXPLOIT_TOKEN environment variable is missing")
      end

      initialize(token)
    end

    # method to start and spawn the repeater process
    def start_repeater : Process
      Log.info { "Starting repeater" }
      # Starting a repeater process, letting it run in the background
      repeater_commands = [
        "nexploit-cli", "repeater",
        "--token", @token,
        "--id", @scan.repeater,
      ]

      repeater_process = ProcessHandler.new
      repeater_process.spawn_process(repeater_commands)
    end

    def cleanup
      begin
        Log.info { "Stopping repeater process" }
        @repeater_process.signal(:int)
      rescue e : Exception
        Log.error(exception: e) { "Error stopping repeater's process" }
      end
    end

    def run_check(scan_name : String, tests : String | Array(String)?, target : Target)
      Log.info { "Running check #{tests} on #{target}" }

      # Verify Repeater process
      raise SecTester::Error.new("Repeater process isn't running: #{repeater_output}") unless @repeater_process.exists?

      # Start a new scan
      scan_id = @scan.start(scan_name: scan_name, tests: tests, target: target)

      Log.info { "Scan process started, polling on results with scan ID: #{scan_id}" }
      # Polling for scan results

      @scan.poll(
        timeout: 20.minutes,
        on_issue: true,
      )
    end

    def run_check(scan_name : String, tests : String | Array(String)?)
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
        url: "http://#{addr}?artificial=dummydata",
      )

      yield payload, response
      run_check(scan_name: scan_name, tests: tests, target: target)
    ensure
      payload.try &.close
      response.try &.close
      server.try &.close
    end

    private def repeater_output : String
      (@repeater_process.error? || @repeater_process.output?).to_s
    end

    private def wait_for_repeater
      10.times do |i|
        break if @scan.repeater_running?
        sleep 1.second
        Log.debug { "Waiting for repeater to start, waited #{i} seconds" }
      end
    end
  end
end
