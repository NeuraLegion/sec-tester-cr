# sec_tester

A library to allow the usage of NexPloit security scanner inside of the Crystal SPECS unit testing flow

For support and help visit the [NeuraLegion Discord](https://discord.gg/jy9BB7twtG)

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

1. Register for an account at [signup](https://app.neuralegion.com/signup)
2. install the [nexploit-cli](https://www.npmjs.com/package/@neuralegion/nexploit-cli) utility
3. Generate an API key from your [UI](https://docs.neuralegion.com/docs/manage-your-personal-account#manage-your-personal-api-keys-authentication-tokens)
4. Generate a Repeater ID from your [UI](https://docs.neuralegion.com/docs/manage-repeaters#create-a-new-repeater)
5. The preferred approach is to setup your ID and API-Key as ENV vars `NEXPLOIT_TOKEN` for API key, and `NEXPLOIT_REPEATER` for the repeater ID.

### Use Inside Specs

```crystal
require "sec_tester"

it "tests my app for XSS" do
  server = HTTP::Server.new do |context|
    name = URI.decode_www_form(context.request.query_params["name"]?.to_s)

    context.response.content_type = "text/html"
    context.response << <<-EOF
      <html>
        <body>
          <h1>Hello, world!</h1>
          <p>#{name}</p>
        </body>
      </html>
      EOF
  end

  addr = server.bind_unused_port
  spawn do
    server.listen
  end

  tester = SecTester::Test.new
  tester.run_check(
    scan_name: "UnitTestingScan - XSS",
    test_name: "xss",
    target: SecTester::Target.new("http://#{addr}/?name=jhon")
  )
ensure
  server.try &.close
  tester.try &.cleanup
end

```

### Manual target configurations

The following example shows how to configure a target manually.
this is very useful to control expected response from the target.

```crystal
target: SecTester::Target.new(
  method: "GET",
  url: "http://#{addr}/?name=jhon",
  response_headers: HTTP::Headers{"Content-Type" => "text/html"}
  )
```

## Contributing

1. Fork it (<https://github.com/NeuraLegion/sec_tester/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Bar Hofesh](https://github.com/bararchy) - creator and maintainer
