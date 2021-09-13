require "./scan.cr"

module SecTester
  class Test
    Log = SecTester::Log.for("Test")

    @token : String
    @repeater : String

    @repeater_process : Process
    @scan : Scan

    def initialize(@token : String, @repeater : String)
      @scan = Scan.new(token: @token, repeater: @repeater)
      @repeater_process = start_repeater
      sleep 10.seconds # Let repeatr start
      raise SecTester::Error.new("Repeater process isn't running: #{@repeater_process.error?.to_s}") unless @repeater_process.exists?
    end

    def initialize
      unless token = ENV["NEXPLOIT_TOKEN"]?
        raise SecTester::Error.new("NEXPLOIT_TOKEN environment variable is missing")
      end

      unless repeater = ENV["NEXPLOIT_REPEATER"]?
        raise SecTester::Error.new("NEXPLOIT_REPEATER environment variable is missing")
      end

      @token = token
      @repeater = repeater
      @scan = Scan.new(token: token, repeater: repeater)
      @repeater_process = start_repeater
      sleep 10.seconds # Let repeatr start
      raise SecTester::Error.new("Repeater process isn't running: #{@repeater_process.error?.to_s}") unless @repeater_process.exists?
    end

    # method to start and spawn the repeater process
    def start_repeater : Process
      Log.info { "Starting repeater" }
      # Starting a repeater process, letting it run in the background
      repeater_commands = [
        "nexploit-cli", "repeater",
        "--token", @token,
        "--id", @repeater,
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

    def run_check(scan_name : String, test_name : String, target : Target)
      Log.info { "Running check #{test_name} on #{target}" }

      # Start a new scan
      scan_id = @scan.start(scan_name: scan_name, test_name: test_name, target: target)

      Log.info { "Scan process started, polling on results with scan ID: #{scan_id}" }
      # Polling for scan results

      @scan.poll(
        timeout: 20.minutes,
        on_issue: true,
      )
    end
  end
end
