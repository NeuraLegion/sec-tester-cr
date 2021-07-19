module SecTester
  class ProcessHandler
    Log = SecTester::Log.for("ProcessHandler")

    @update_interval : Time::Span = 30.seconds
    @timeout : Time::Span? = 30.minutes

    getter! output : IO::Memory
    getter! error : IO::Memory
    @start_time : Time::Span = Time.monotonic

    getter? done = false
    getter? failed = false

    protected def spawn_process(command_args) : Process
      Log.info { "Starting #{self.class} with the command: #{command_args.join(' ')}" }

      @error = IO::Memory.new
      @output = IO::Memory.new

      @done = @failed = false
      @start_time = Time.monotonic
      begin
        Process.new("/usr/bin/env", command_args, output: output, error: error)
      rescue e : Exception
        Log.error { "Error starting #{self.class}: #{e.inspect_with_backtrace} - #{error}" }
        raise SecTester::Error.new("Error starting #{self.class}", cause: e)
      end
    end

    protected def elapsed_time : Time::Span
      Time.monotonic - @start_time
    end

    def call(ps : Process) : String
      update(ps)

      data = output.to_s.presence
      raise "Empty output" unless data
      Log.info { "Process Output: #{data}" }

      data.strip
    end

    def call?(ps : Process)
      call(ps)
    rescue e : Exception
      Log.error { "Error executing #{self.class}#call: #{e.inspect_with_backtrace}" }
      nil
    end

    protected def update(ps : Process)
      while ps.exists?
        Log.debug { "#{self.class} process running for #{elapsed_time}" }
        sleep @update_interval
        if (timeout = @timeout) && elapsed_time > timeout
          @done = @failed = true
          ps.signal(:term)
          raise "Process timeouted after #{timeout}"
        end
      end
      unless error.empty?
        Log.error { "Error running #{self.class}: #{error}" }
        @failed = true
      end
      Log.info { "Done running #{self.class}" }
      @done = true
    end
  end
end
