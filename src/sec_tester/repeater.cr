require "socket_io"
require "http"

module SecTester
  class Repeater
    @api_key : String
    @socket : SocketIO::Client
    getter id : String = ""

    def initialize(@api_key : String, hostname : String = "app.brightsec.com")
      @socket = SocketIO::Client.new(host: hostname, path: "/api/ws/v1/", namespace: "/workstations")
      @socket.connect(
        data: <<-EOF
          {"token":"#{@api_key}","domain":"#{System.hostname}"}
          EOF
      )
      deploy
    end

    def deploy
      @socket.send("\"deploy\"")
    end

    def close
      @socket.send("\"undeploy\"")
      @socket.close
    end

    def run
      @socket.on_data do |packet|
        Log.debug { "Repeater Packet: #{packet}" }
        data = packet.data
        case data.as_a[0].as_s
        when "deployed"
          @id = data[1]["repeaterId"].as_s
          Log.debug { "Repeater deployed id: #{@id}" }
        when "undeployed"
          @id = ""
        when "error"
          Log.error { "Repeater Error: #{data[1]["name"]} - #{data[1]["message"]}" }
        when "request"
          if id = packet.id
            handle_request(data[1], id)
          end
        end
      end
    end

    def handle_request(request : JSON::Any, id : Int64)
      request_data = request.as_h
      headers = HTTP::Headers.new
      request_data["headers"].as_h.each do |key, value|
        headers[key] = value.as_s
      end
      response = HTTP::Client.exec(
        method: request_data["method"].as_s,
        url: request_data["url"].as_s,
        headers: headers,
        body: request_data["body"]?.try &.as_s
      )
      hash = Hash(String, String).new
      response.headers.each do |key, value|
        hash[key] = value.first
      end
      data = {
        "protocol":   "http",
        "statusCode": response.status_code,
        "body":       response.body.to_s,
        "headers":    hash,
      }

      @socket.send(
        data: data.to_json,
        id: id,
        type: :ack
      )
    rescue e : Exception
      data = {
        protocol:  "http",
        errorCode: "#{e.class}",
        message:   e.message,
      }
      @socket.send(
        data: data.to_json,
        id: id,
        type: :ack
      )
    end
  end
end
