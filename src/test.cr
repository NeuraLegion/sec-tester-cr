module SecTester
  class Test
    Log = SecTester::Log.for("Test")

    @token : String
    @repeater : String

    @repeater_process : Process

    def initialize(@token : String, @repeater : String)
      @repeater_process = start_repeater
      sleep 10.seconds # Let repeatr start
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
      @repeater_process = start_repeater
      sleep 10.seconds # Let repeatr start
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

    def run_check(scan_name : String, test_name : String, target_url : String)
      Log.info { "Running check #{test_name} on #{target_url}" }

      # Start a new scan with the spawned repeater process
      scan_commands = [
        "nexploit-cli", "scan:run",
        "--test", test_name,
        "--name", scan_name,
        "--crawler", target_url,
        "--token", @token,
        "--repeater", @repeater,
      ]
      scan_process = ProcessHandler.new

      # Fetching scan ID
      scan_process.call(scan_process.spawn_process(scan_commands))
      scan_id = scan_process.output.to_s

      Log.info { "Scan process started, polling on results with scan ID: #{scan_id}" }

      # Polling for scan results
      poll_commands = [
        "nexploit-cli", "scan:polling",
        "--token", @token,
        "--interval", "30s",
        "--breakpoint", "any",
        "--timeout", "20m",
        scan_id,
      ]

      poll_process = ProcessHandler.new
      poll_process.call(poll_process.spawn_process(poll_commands))
    end
  end
end
