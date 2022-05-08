require "commander"
require "tallboy"
require "./sec_tester.cr"

cli = Commander::Command.new do |cmd|
  cmd.use = "sec_tester_cli"
  cmd.long = "Security testing CLI using Bright SecTester"

  cmd.flags.add do |flag|
    flag.name = "token"
    flag.short = "-t"
    flag.long = "--token"
    flag.description = "Bright token to use for the scan."
    flag.default = ""
  end

  cmd.flags.add do |flag|
    flag.name = "url"
    flag.short = "-u"
    flag.long = "--url"
    flag.description = "Target URL to scan"
    flag.default = "localhost"
  end

  cmd.flags.add do |flag|
    flag.name = "severity"
    flag.short = "-s"
    flag.long = "--severity"
    flag.description = "Set the severity level of the scan, can be low, medium, high."
    flag.default = "low"
  end

  cmd.run do |options, arguments|
    tester = SecTester::Test.new(token: options.string["token"])

    chan = Channel(Nil | Exception).new(1)
    done = Atomic(Int32).new(0)

    severity = case options.string["severity"]
               when "medium"
                 SecTester::Severity::Medium
               when "high"
                 SecTester::Severity::High
               else
                 SecTester::Severity::Low
               end

    spawn do
      begin
        tester.run_check(
          scan_name: "UnitTestingScan - XSS",
          tests: SecTester::SUPPORTED_TESTS.to_a,
          target: SecTester::Target.new(
            url: options.string["url"]
          ),
          severity_threshold: severity
        )
        chan.send(nil)
      rescue e : Exception
        chan.send(e)
      ensure
        done.add(1)
      end
    end

    loop do
      break if (done.get == 1)

      table = Tallboy.table do
        header ["Running", "", tester.scan_duration.to_s]
        header ["Name", "Severity", "Link"]

        tester.issues.each do |issue|
          row [
            issue.name,
            issue.severity,
            "#{SecTester::Scan::BASE_URL}#{issue.issue_url}",
          ]
        end
      end

      system("clear")
      print "\r#{table.render}"
      sleep 0.5
    end
  end
end

Commander.run(cli, ARGV)
