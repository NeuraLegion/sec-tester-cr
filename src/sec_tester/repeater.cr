require "socket_io"
require "http"
require "uuid"

module SecTester
  class Repeater
    @api_key : String
    @socket : SocketIO::Client
    @running : Bool = false
    getter id : String = ""

    def initialize(@api_key : String, hostname : String = "app.brightsec.com")
      @running = true
      @socket = SocketIO::Client.new(
        host: hostname,
        path: "/api/ws/v1/",
        namespace: "/workstations",
        decoder: SocketIO::Decoders::MsgpackDecoder.new
      )
      @socket.connect(
        data: {
          token:  @api_key,
          domain: "#{System.hostname}##{UUID.random}",
        }
      )
      deploy
    end

    def deploy
      @socket.emit("deploy")
    end

    def close
      @socket.emit("undeploy")
      @socket.close
      @running = false
    end

    def run
      # handle request events
      @socket.on("request") do |event|
        handle_request(event)
      end

      # hamdle deployed events
      @socket.on("deployed") do |event|
        next unless data = event.data
        @id = data.first["repeaterId"].as_s
        Log.debug { "Repeater deployed id: #{@id}" }
      end

      # handle undeployed events
      @socket.on("undeployed") do |_|
        @id = ""
        @socket.off("undeployed")
      end

      Log.debug { "Repeater started" }
    end

    def handle_request(request_event : SocketIO::Event)
      # fail fast if no request data or id
      return unless data = request_event.data
      return unless request_event.id

      request_data = EventData.from_json(data[0].to_json)

      headers = HTTP::Headers.new

      request_data.headers.each do |key, value|
        headers[key] = value.to_s
      end

      if request_data.encoding == "base64" && request_data.body.presence
        body = Base64.decode_string(request_data.body.to_s)
      else
        body = request_data.body
      end

      # Make request
      response = HTTP::Client.exec(
        method: request_data.method,
        url: request_data.url,
        headers: headers,
        body: body
      )
      # prepare response data
      hash = Hash(String, String).new
      response.headers.each do |key, value|
        hash[key] = value.first
      end

      if request_data.encoding == "base64"
        data = {
          protocol:   "http",
          statusCode: response.status_code,
          body:       Base64.strict_encode(response.body.to_s),
          headers:    hash,
          encoding:   "base64",
        }
      else
        data = {
          protocol:   "http",
          statusCode: response.status_code,
          body:       response.body.to_s,
          headers:    hash,
        }
      end
      # send response as ack
      request_event.ack(data)
    rescue e : Exception
      Log.error(exception: e) { "Error handling request: #{e.inspect_with_backtrace}" }
      data = {
        protocol:  "http",
        errorCode: "#{e.class}",
        message:   e.message,
      }
      request_event.ack(data)
    end

    # This is the struct of the event data
    struct EventData
      include JSON::Serializable

      getter method : String
      getter url : String
      getter headers : Hash(String, String | Array(String))
      getter body : String?

      # Extra fields
      getter encoding : String?
      @[JSON::Field(key: "maxContentSize")]
      getter max_content_size : Int32?
      getter timeout : Int32?
      getter decompress : Bool?
    end
  end
end
