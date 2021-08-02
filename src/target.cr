require "har"
require "uri"

module SecTester
  class Target
    getter url : String
    getter method : String
    getter headers : HTTP::Headers
    getter body : String

    def initialize(@url : String)
      @method = "GET"
      @headers = HTTP::Headers.new
      @headers["Host"] = URI.parse(@url).hostname.to_s
      @body = ""
    end

    def initialize(@method : String, @url : String, @headers : HTTP::Headers = HTTP::Headers.new, @body : String = "")
    end

    def to_har : String
      HAR::Log.new(
        entries: [
          HAR::Entry.new(
            request: HAR::Request.new(
              method: @method,
              url: @url,
              headers: @headers,
              post_data: PostData.new(text: @body)
            ),
            response: HAR::Response.new(
              status: 200,
              status_text: "OK",
              http_version: "HTTP/1.1",
              content: ""
            )
          ),
        ]
      ).to_json
    end
  end
end
