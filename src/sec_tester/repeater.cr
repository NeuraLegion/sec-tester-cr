require "socket_io"
require "http"

module SecTester
  class Repeater
    @api_key : String
    @socket : SocketIO::Client
    getter id : String = ""

    def initialize(@api_key : String, hostname : String = "app.brightsec.com")
      @socket = SocketIO::Client.new(
        host: hostname,
        path: "/api/ws/v1/",
        namespace: "/workstations",
        decoder: SocketIO::Decoders::MsgpackDecoder.new
      )
      @socket.connect(
        data: {
          token:  @api_key,
          domain: System.hostname,
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
      @socket.on("undeployed") do |event|
        @id = ""
      end

      Log.debug { "Repeater started" }
    end

    def handle_request(request_event : SocketIO::Event)
      # fail fast if no request data or id
      return unless data = request_event.data
      return unless request_event.id

      request_data = data[0].try &.as_h?
      return unless request_data

      headers = HTTP::Headers.new
      request_data["headers"].as_h.each do |key, value|
        headers[key] = value.as_s
      end
      # Make request
      response = HTTP::Client.exec(
        method: request_data["method"].as_s,
        url: request_data["url"].as_s,
        headers: headers,
        body: request_data["body"]?.try &.as_s
      )
      # prepare response data
      hash = Hash(String, String).new
      response.headers.each do |key, value|
        hash[key] = value.first
      end

      data = {
        protocol:   "http",
        statusCode: response.status_code,
        body:       response.body.to_s,
        headers:    hash,
      }
      # send response as ack
      request_event.ack(data)
    rescue e : Exception
      data = {
        protocol:  "http",
        errorCode: "#{e.class}",
        message:   e.message,
      }
      request_event.ack(data)
    end
  end
end
