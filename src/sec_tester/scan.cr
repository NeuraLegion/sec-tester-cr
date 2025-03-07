require "json"
require "colorize"
require "./errors.cr"

module SecTester
  class Scan
    getter repeater : Repeater
    getter scan_duration : Time::Span = Time::Span.new
    getter issues
    getter entry_points : Atomic(Int32) = Atomic.new(0)
    getter total_params : Atomic(Int32) = Atomic.new(0)
    getter total_requests : Atomic(Int64) = Atomic.new(0_i64)
    getter scan_status : String = ""
    getter base_url : String = ENV["CLUSTER_URL"]? || "https://app.brightsec.com"

    @scan_id : String?
    @running : Bool = false
    @issues : Set(SecTester::Issue) = Set(SecTester::Issue).new

    def initialize(@token : String)
      validate_token!
      @repeater = Repeater.new(api_key: @token, hostname: URI.parse(@base_url).host.to_s)
      spawn do
        @repeater.run
      end
      # Wait for repeater to get ID
      # Don't wait forever, if repeater is not running, we will get an error
      # after 30 seconds

      30.times do
        break unless @repeater.id.empty?
        sleep 1.second
        Log.debug { "Waiting for repeater to get ID" }
      end
    end

    private def get_headers : HTTP::Headers
      headers = HTTP::Headers.new
      headers["Authorization"] = "Api-Key #{@token}"
      headers["Content-Type"] = "application/json"
      headers["Accept"] = "application/json"
      headers["Host"] = URI.parse(@base_url).host.to_s

      Log.debug { "Setting headers: #{headers}" }

      headers
    end

    def start(scan_name : String, tests : String | Array(String)?, target : Target, options : Options) : String
      # The API supports only Nil or Array(String) so we normalize the input
      tests = [tests] if tests.is_a?(String)

      # Unless tests are nil, we need to validate them
      if tests
        unless tests.all?(&.in?(SUPPORTED_TESTS))
          raise SecTester::Error.new("Unsupported tests: #{tests} (supported: #{SUPPORTED_TESTS})")
        end
      end

      @running = true
      new_scan_url = "#{@base_url}/api/v1/scans"

      ep_id = create_ep(target, options)

      # Information about caller
      ci_name = case
                when ENV["GITLAB_CI"]?
                  "gitlab"
                when ENV["CIRCLECI"]?
                  "circleci"
                when ENV["GITHUB_ACTION"]?
                  "github_actions"
                when ENV["JENKINS_HOME"]?
                  "jenkins"
                when ENV["TRAVIS"]?
                  "travis"
                else
                  if ENV["CI"]?
                    "other"
                  else
                    "unknown"
                  end
                end

      body = {
        "name":                 scan_name,
        "module":               "dast",
        "tests":                tests,
        "entryPointIds":        [ep_id],
        "repeaters":            [@repeater.id],
        "attackParamLocations": options.param_locations,
        "discoveryTypes":       options.crawl? ? ["crawler", "archive"] : ["archive"],
        "crawlerUrls":          options.crawl? ? [target.url] : nil,
        "smart":                options.smart_scan?,
        "skipStaticParams":     options.skip_static_parameters?,
        "projectId":            options.project_id || get_first_project_id, # to make sure the scan is created in the right project
        "slowEpTimeout":        options.slow_ep_timeout,
        "targetTimeout":        options.target_timeout,
        "authObjectId":         options.auth_object_id,
        "templateId":           options.template_id,
        "info":                 {
          "source": "utlib",
          "client": {
            "name":    "sec_tester_crystal",
            "version": SecTester::VERSION,
          },
          "provider": ci_name,
        },
      }.to_json

      Log.debug { "Sending body request: #{body}" }

      response = send_with_retry(method: "POST", url: new_scan_url, body: body)
      raise SecTester::Error.new("Error starting scan: #{response.body}") unless response.status.success?
      @scan_id = JSON.parse(response.body.to_s)["id"].to_s
    rescue e : JSON::ParseException
      raise SecTester::Error.new("Error starting new scan: #{e.message} response: #{response.try &.body.to_s}")
    end

    def poll(on_issue : Bool = false, timeout : Time::Span? = nil, interval : Time::Span = 5.seconds, severity_threshold : Severity = :low)
      raise SecTester::Error.new("Cannot poll scan results without scan_id, make sure to 'start' the scan before polling") unless @scan_id

      time_started = Time.monotonic

      loop do
        sleep interval

        response = poll_call
        response_json = JSON.parse(response.body.to_s)

        @scan_duration = (response_json["elapsed"].as_i64.milliseconds rescue 0.milliseconds) # From time to times the API will send strange values
        @entry_points.set(response_json["entryPoints"].as_i)
        @total_params.set(response_json["totalParams"].as_i)
        @total_requests.set(response_json["requests"].as_i64)
        get_issues.each { |issue| @issues << issue unless @issues.includes?(issue) }
        @scan_status = response_json["status"].as_s

        Log.debug { "Polling scan #{@scan_id} -- duration: #{@scan_duration} -- status: #{@scan_status}" }

        should_raise = false
        if on_issue
          if response_json["issuesLength"].as_i > 0
            Log.warn { "Scan has #{response_json["issuesLength"]} issues, Analyzing based on severity: #{severity_threshold}".colorize.yellow }
            stop

            get_issues.each do |issue|
              case severity_threshold
              when Severity::Low
                next unless {"low", "medium", "high", "critical"}.any? { |sev| issue.severity.downcase == sev }
              when Severity::Medium
                next unless {"medium", "high", "critical"}.any? { |sev| issue.severity.downcase == sev }
              when Severity::High
                next unless {"high", "critical"}.any? { |sev| issue.severity.downcase == sev }
              when Severity::Critical
                next unless issue.severity.downcase == "critical"
              end

              should_raise = true
              message = String.build do |str|
                str << "\n"
                str << "Name: ".colorize.cyan.bold
                str << issue.name.colorize.white.bold
                str << "\n"
                str << "Severity: ".colorize.cyan.bold
                str << color_severity(issue.severity)
                str << "\n"
                str << "Link to Issue: ".colorize.cyan.bold
                str << "#{@base_url}#{issue.issue_url}".colorize.blue.bold
                str << "\n"
                str << "Details: ".colorize.cyan.bold
                str << issue.details.gsub("\n", " ").colorize.white.bold
                str << "\n"
                str << "Remediation: ".colorize.cyan.bold
                str << issue.remedy.gsub("\n", " ").colorize.white.bold
                str << "\n"
                str << "Extra Details: ".colorize.cyan.bold
                issue.comments.each do |comment|
                  str << comment.to_s.gsub("\n", " ").colorize.white.bold
                  str << "\n"
                end
                str << "\n"
                str << "External Resources: ".colorize.cyan.bold
                str << issue.resources.join(", ").colorize.blue.bold
                str << "\n"
              end
              Log.warn { message }
              STDERR.puts message
            end
            raise IssueFound.new("Scan has issues, see above for details") if should_raise
          end
        end

        unless {"running", "pending"}.any? { |status| response_json["status"] == status }
          Log.info { "Scan #{response_json["status"]}, stop polling".colorize.green }
          stop
          break
        end

        if timeout
          if (Time.monotonic - time_started) > timeout
            Log.warn { "Scan timed out, stop polling".colorize.yellow }
            stop
          end
        end
      end
    end

    def stop
      if @running
        @running = false
        raise SecTester::Error.new("Cannot stop scan without scan_id, make sure to 'start' the scan before stopping") unless @scan_id
        stop_url = "#{@base_url}/api/v1/scans/#{@scan_id}/stop"

        Log.debug { "Stopping scan #{@scan_id}" }

        # Ensure scane is running
        response = poll_call
        response_json = JSON.parse(response.body.to_s)
        if response_json["status"].as_s == "running"
          # Stop Scan
          send_with_retry(method: "GET", url: stop_url)
        end
        @repeater.close
      end
    end

    # method to check if repeater is up and running
    def repeater_running? : Bool
      repeater_url = "#{@base_url}/api/v1/repeaters/#{@repeater.id}"

      response = send_with_retry(method: "GET", url: repeater_url)
      JSON.parse(response.body.to_s)["status"].to_s == "connected"
    rescue e : JSON::ParseException
      raise SecTester::Error.new("Error checking repeater status: #{e.message} response: #{response.try &.body.to_s}")
    end

    private def color_severity(severity : String)
      case severity.downcase
      when "low"
        severity.colorize.blue.bold
      when "medium"
        severity.colorize.yellow.bold
      when "high"
        severity.colorize(Colorize::ColorRGB.new(255, 94, 5)).bold
      when "critical"
        severity.colorize.red.bold
      else
        severity
      end
    end

    private def validate_token!
      check_user_url = "#{@base_url}/api/v1/scans/summary"

      response = send_with_retry(method: "GET", url: check_user_url)
      if response.status.unauthorized?
        raise SecTester::Error.new("API token is invalid for #{@base_url}, please generate a new one!. response: #{response.try &.body.to_s}")
      end
    end

    private def get_issues : Array(Issue)
      issues_url = "#{@base_url}/api/v1/scans/#{@scan_id}/issues"

      response = send_with_retry("GET", issues_url)
      Array(Issue).from_json(response.body.to_s)
    rescue e : JSON::ParseException
      raise SecTester::Error.new("Error getting issue data: #{e.message} response: #{response.try &.body.to_s}")
    end

    private def create_ep(target : Target, options : Options) : String # Returns the EP ID to be used for the scan
      project_id = options.project_id || get_first_project_id
      new_ep_url = "#{@base_url}/api/v2/projects/#{project_id}/entry-points"

      body = {
        request:    target.to_json,
        repeaterId: @repeater.id,
      }.to_json

      response = send_with_retry("POST", new_ep_url, body: body)
      if response.status.conflict? # If EP already exists, we need to get it's ID
        Log.debug { "EP already exists, getting ID" }
        url_from_header = response.headers["Location"].to_s
        ep_id = url_from_header.split("/").last.to_s
      else
        ep_id = JSON.parse(response.body.to_s)["id"].to_s
      end
      ep_id.presence || raise(SecTester::Error.new("Error creating entry point: #{response.body}"))
    rescue e : JSON::ParseException
      raise SecTester::Error.new(<<-EOF
        Error creating entry point: #{target.method} #{target.url}
        Error message: #{e.message}
        response status: #{response.try &.status_code}
        response body: #{response.try &.body.to_s}
        EOF
      )
    end

    private def get_first_project_id : String
      # This will get the "predefind"\"default" project
      projects_url = "#{@base_url}/api/v2/projects?predefined=true"

      response = send_with_retry("GET", projects_url)

      JSON.parse(response.body.to_s)["items"][0]["id"].to_s
    rescue e : JSON::ParseException
      raise SecTester::Error.new("Error getting project ID: #{e.message} response: #{response.try &.body.to_s}")
    end

    private def poll_call : HTTP::Client::Response
      poll_url = "#{@base_url}/api/v1/scans/#{@scan_id}"
      send_with_retry("GET", poll_url)
    end

    private def send_with_retry(method : String, url : String, headers : HTTP::Headers = get_headers, body : HTTP::Client::BodyType = nil) : HTTP::Client::Response
      response = HTTP::Client.exec(
        method: method,
        url: url,
        headers: headers,
        body: body
      )

      5.times do
        if response.status_code >= 500
          Log.error { "Retrying #{method} #{url} - #{response.status_code} - #{response.body}" }
          sleep 5
          response = HTTP::Client.exec(
            method: method,
            url: url,
            headers: headers,
            body: body
          )
        else
          break
        end
      end

      response
    end
  end
end
