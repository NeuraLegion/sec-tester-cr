# sec_tester

A library to allow the usage of NexPloit security scanner inside of the Crystal SPECS unit testing flow

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     sec_tester:
       github: NeuraLegion/sec_tester
   ```

2. Run `shards install`

## Usage

### Dependencies

To use the library you will first need to

1. Register for an account at (signup)[https://nexploit.app/signup]

2. install the (nexploit-cli)[https://www.npmjs.com/package/@neuralegion/nexploit-cli] utility

3. Generate an API key from your (UI)[https://kb.neuralegion.com/#/guide/np-web-ui/advanced-set-up/managing-personal-account?id=managing-your-personal-api-keys-authentication-tokens]

4. Generate a Repeater ID from your (UI)[https://kb.neuralegion.com/#/guide/np-web-ui/advanced-set-up/managing-repeaters]

5. The preferred approach is to setup your ID and API-Key as ENV vars `NEXPLOIT_TOKEN` for API key, and `NEXPLOIT_REPEATER` for the repeater ID.

### Use Inside Specs

```crystal
require "sec_tester"

it "starts a new scan" do
  server = HTTP::Server.new do |context|
    command = URI.decode_www_form(context.request.query_params["command"]?.to_s)

    context.response.content_type = "text/html"
    context.response << <<-EOF
      <html>
        <body>
          <h1>Hello, world!</h1>
          <p>#{`#{command}`}</p>
        </body>
      </html>
      EOF
  end

  addr = server.bind_unused_port
  spawn do
    server.listen
  end

  tester = SecTester::Test.new
  tester.run_check(scan_name: "UnitTestingScan", test_name: "osi", target_url: "http://#{addr}/?command=time")
ensure
  server.try &.close
  tester.try &.cleanup
end

```

## Contributing

1. Fork it (<https://github.com/NeuraLegion/sec_tester/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Bar Hofesh](https://github.com/bararchy) - creator and maintainer
