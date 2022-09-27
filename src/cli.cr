require "commander"
require "tallboy"
require "./sec_tester.cr"
require "opentelemetry-instrumentation"

# OpenTelemetry can be configured in all cases. The default behavior
# is to use a NullExporter, so that data is recorded, and is sent to
# an exporter, but the exporter does nothing with them.
#
# Sending traces to a platform like New Relic then just requires the
# setting of a few environment variables.
#
# - OTEL_TRACES_EXPORTER=http
#
#   This sets the exporter for traces at the HTTP exporter.
#
# - OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://otlp.nr-data.net:4318/v1/traces
#
#   This provides the OTLP/HTTP exporter an endpoint to send traces to.
#
# - OTEL_EXPORTER_OTLP_TRACES_HEADERS="api-key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxNRAL"
#
#   This specifies any specific HTTP headers that need to be set, such as the `api-key` header.
#
# For other platforms, just change the TRACES_ENDPOINT and TRACES_HEADERS
# values as appropriate for that platform.
OpenTelemetry.configure do |config|
  config.service_version = SecTester::VERSION
  config.service_name = "BrightSec Sec-Tester-CLI"
end

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
    flag.name = "name"
    flag.short = "-n"
    flag.long = "--name"
    flag.description = "Set the name of the scan."
    flag.default = "sec_tester_cli"
  end

  cmd.run do |options|
    tester = SecTester::Test.new(token: options.string["token"])

    chan = Channel(Nil | Exception).new(1)
    done = Atomic(Int32).new(0)

    spawn do
      begin
        tester.run_check(
          scan_name: options.string["name"],
          tests: SecTester::SUPPORTED_TESTS.to_a,
          target: SecTester::Target.new(
            url: options.string["url"]
          ),
          options: SecTester::Options.new(
            crawl: true,
          ),
          on_issue: false,
          timeout: nil
        )
        chan.send(nil)
      rescue e : Exception
        chan.send(e)
      ensure
        done.add(1)
      end
    end

    reported_issues = Set.new(tester.issues.to_a)

    loop do
      table = Tallboy.table do
        header [tester.scan_status.capitalize, "", tester.scan_duration.to_s]
        header ["Total URLs", "", tester.entry_points.get.to_s]
        header ["Total Parameters", "", tester.total_params.get.to_s]
        header ["Name", "Severity", "Link"]

        current_issues = tester.issues.to_a
        if current_issues.size != reported_issues.size
          current_set = Set.new(current_issues)
          new_set = current_set - reported_issues

          new_set.each do |issue|
            OpenTelemetry.trace.in_span("ISSUE FOUND: #{issue.name}") do |span|
              span.status.error!("#{issue.severity}: #{issue.name}")
              span.consumer!
              span["brightsec.name"] = issue.name
              span["brightsec.severity"] = issue.severity
              span["brightsec.url"] = "#{SecTester::Scan::BASE_URL}#{issue.issue_url}"
            end
          end

          reported_issues = current_set
        end

        (tester.issues.to_a.sort_by &.severity).each do |issue|
          row [
            issue.name,
            issue.severity,
            "#{SecTester::Scan::BASE_URL}#{issue.issue_url}",
          ]
        end
      end

      system("clear")
      print "\r#{table.render}"
      break if (done.get == 1)
      sleep 0.5
    end
  end
end

Commander.run(cli, ARGV)
