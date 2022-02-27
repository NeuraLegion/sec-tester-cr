require "har"
require "uri"

module SecTester
  class Target
    ACCEPTED_METHODS = {"GET", "PUT", "POST", "PATCH", "DELETE", "COPY", "HEAD", "OPTIONS", "LINK", "UNLINK", "PURGE", "LOCK", "UNLOCK", "PROPFIND", "VIEW"}

    property url : String
    property method : String
    property headers : HTTP::Headers
    property body : String
    property response_headers : HTTP::Headers
    property response_body : String
    property response_status : Int32

    def initialize(url : String)
      headers = HTTP::Headers.new
      headers["Host"] = URI.parse(url).hostname.to_s
      initialize(
        method: "GET",
        url: url,
        headers: headers,
        body: "",
        response_headers: HTTP::Headers{"Content-Type" => "text/html"},
        response_body: "",
        response_status: 200
      )
    end

    def initialize(
      @method : String,
      @url : String,
      @headers : HTTP::Headers = HTTP::Headers.new,
      @body : String = "",
      @response_headers : HTTP::Headers = HTTP::Headers.new,
      @response_body : String = "",
      @response_status : Int32 = 200
    )
      # Small hack to ensure localhost scans run
      # the NL\BrightSec scanner doesn't allow for `localhost` as a hostname
      if URI.parse(@url).host == "localhost"
        uri = URI.parse(@url)
        uri.host = "127.0.0.1"
        @url = uri.to_s
      end

      # Verify method and url
      verify_url
      verify_method
    end

    def to_har : String
      verify_method
      har = HAR::Data.new(
        log: HAR::Log.new(
          entries: [
            HAR::Entry.new(
              request: HAR::Request.new(
                method: @method.upcase,
                url: @url,
                http_version: "HTTP/1.1",
                headers: @headers.map { |k, v| HAR::Header.new(name: k, value: v.first) },
                post_data: HAR::PostData.new(
                  text: @body,
                  mime_type: @headers["Content-Type"]? || ""
                )
              ),
              response: HAR::Response.new(
                status: 200,
                status_text: "OK",
                http_version: "HTTP/1.1",
                headers: @response_headers.map { |k, v| HAR::Header.new(name: k, value: v.first) },
                content: HAR::Content.new(
                  size: 0,
                  text: @response_body
                ),
                redirect_url: ""
              ),
              time: 0.0,
              timings: HAR::Timings.new(
                send: 0.0,
                wait: 0.0,
                receive: 0.0
              ),
            ),
          ]
        )
      )
      Log.debug { "Har: #{har.to_json}" }
      har.to_json
    end

    private def verify_method
      raise Error.new("Invalid method passed to target: #{@method}") unless @method.in?(ACCEPTED_METHODS)
    end

    private def verify_url
      uri = URI.parse(@url)
      if uri.scheme.nil? || uri.scheme.to_s.empty?
        raise Error.new("Invalid URL passed to target: #{@url}")
      end

      if uri.host.nil? || uri.host.to_s.empty?
        raise Error.new("Invalid URL passed to target: #{@url}")
      end
    end
  end
end
