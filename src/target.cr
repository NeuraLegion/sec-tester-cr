require "har"
require "uri"

module SecTester
  class Target
    getter url : String
    getter method : String
    getter headers : HTTP::Headers
    getter body : String
    getter response_headers : HTTP::Headers
    getter response_body : String

    def initialize(@url : String)
      @method = "GET"
      @headers = HTTP::Headers.new
      @headers["Host"] = URI.parse(@url).hostname.to_s
      @body = ""
      @response_headers = HTTP::Headers.new
      @response_body = ""
    end

    def initialize(
      @method : String,
      @url : String,
      @headers : HTTP::Headers = HTTP::Headers.new,
      @body : String = "",
      @response_headers : HTTP::Headers = HTTP::Headers.new,
      @response_body : String = ""
    )
    end

    def to_har : String
      HAR::Data.new(
        log: HAR::Log.new(
          entries: [
            HAR::Entry.new(
              request: HAR::Request.new(
                method: @method,
                url: @url,
                http_version: "HTTP/1.1",
                headers: @headers.map { |k, v| HAR::Header.new(name: k, value: v.first) },
                post_data: HAR::PostData.new(text: @body)
              ),
              response: HAR::Response.new(
                status: 200,
                status_text: "OK",
                http_version: "HTTP/1.1",
                headers: @response_headers.map { |k, v| HAR::Header.new(name: k, value: v.first) },
                content: HAR::Content.new(
                  size: 0,
                  text: @response_body
                )
              )
            ),
          ]
        )
      ).to_json
    end
  end
end
