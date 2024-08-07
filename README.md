# sec-tester-cr

![example workflow](https://github.com/NeuraLegion/sec-tester-cr/actions/workflows/crystal.yml/badge.svg)

A library to allow the usage of Bright security scanner inside of the Crystal SPECS unit testing flow

For support and help visit the [Bright Discord](https://discord.gg/jy9BB7twtG)

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     sec_tester:
       github: NeuraLegion/sec-tester-cr
   ```

2. Run `shards install`

## Usage

### Dependencies

> **Warning**
>
> To use the library you will first need to complete all of the below steps.

1. Register for an account at [signup](https://app.brightsec.com/signup)
2. Generate an API key from your [UI](https://docs.brightsec.com/docs/manage-your-personal-account#manage-your-personal-api-keys-authentication-tokens)
3. The preferred approach is to setup your API-Key as ENV var `BRIGHT_TOKEN` for API key.

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
    tests: "xss",
    target: SecTester::Target.new("http://#{addr}/?name=jhon")
  )
ensure
  server.try &.close
end

```

### Target Response Configurations

The following example shows how to configure a target manually.
this is very useful to control expected response from the target.

> **Note**
>
> Configuring the response information is very important for the scanner to work properly. and can decrease scan times and improve the accuracy of the scan.

```crystal
target: SecTester::Target.new(
  method: "GET",
  url: "http://#{addr}/?name=jhon",
  response_headers: HTTP::Headers{"Content-Type" => "text/html"},
  response_body: "<html><body><h1>Hello, world!</h1><p>jhon</p></body></html>",
  response_status: 200
  )
```

### Testing Single Function

The following example shows how to test a single function.

```crystal
tester.run_check(scan_name: "UnitTestingScan - XSS - function only", tests: ["xss"]) do |payload, response|
  spawn do
    while payload_data = payload.receive?
      # This is where we send the payload to the function and send back a response
      # In this example we just want to send back the payload
      # as we are testing reflection
      # my_function is a demo function that returns the payload
      response_data = my_function(payload_data)

      # we end up sending the response back to the channel
      response.send(response_data)
    end
  end
end
```

> **Note**
>
> You also have an optional "param_overwrite" parameter that allows you to overwrite the parameters in the request.
> This is useful when your function is expecting a specific data object like JSON or JWT etc..

You can use the `param_overwrite` to overwrite the value to be attacked like:

```crystal
jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
tester.run_check(scan_name: "jwt-testing", tests: ["jwt"], param_overwrite: jwt) do |payload, response|
  spawn do
    while payload_data = payload.receive?
      # This is where we send the payload to the function and send back a response
      # In this example we just want to send back the payload
      # as we are testing reflection
      # my_function is a demo function that returns the payload
      response_data = my_JWT_verification(payload_data)

      # we end up sending the response back to the channel
      response.send(response_data)
    end
  end
end
```

There is also a variant of this interface that accepts target and yields back the whole HTTP::Server::Context.
This is useful if you want to do something with the response body or headers.

```crystal
tester.run_check(scan_name: "UnitTestingScan - XSS - request/response test", target: target, tests: ["xss"]) do |context_channel|
  spawn do
    while context_tuple = context_channel.receive?
      context = context_tuple[:context]
      done_channel = context_tuple[:done_chan]
      input = context.request.query_params["id"]?.to_s
      response_data = my_function(input)

      context.response.headers["Content-Type"] = "text/html"
      context.response.status_code = 200
      context.response.print(response_data)
      done_channel.send(nil) # Important part, make sure to send back nil to the done channel
    end
  end
end
```

### Fail by Severity Threshold

When you want to fail the test by severity threshold, you can use the following example.

```crystal
tester.run_check(
  scan_name: "UnitTestingScan - cookie_security - Skip low",
  tests: ["cookie_security"],
  target: SecTester::Target.new(
    url: "http://#{addr}/",
  ),
  severity_threshold: :medium
)
```

The `severity_threshold` is a `:low`, `:medium`, `:high` or `:critical` value. it allows you to not fail the build if the severity is lower than the threshold.

For example if you want to run the test and fail the build if the severity is `:high` but continue testing if it's `:medium` or `:low`. use the following example.

```crystal
tester.run_check(
  severity_threshold: :high
)
```

If the issues are `:low` or `:medium` the build will continue.

### Scan Options

When running a check you can now pass a few options to the scan. Options are:

1. Smart scan (true\false) - Specify whether to use automatic smart decisions (such as parameter skipping, detection phases and so on) in order to minimize scan time. When this option is turned off, all tests are run on all the parameters, that increases coverage at the expense of scan time.
2. Skip Static Params (true\false) - Specify whether to skip static parameters to minimize scan time.
3. Specify Project ID for the scan - [manage-projects](https://docs.brightsec.com/docs/manage-projects)
4. Parameter locations: `param_locations` - Specify the parameter locations to scan in the Request. this opens supports `body`, `query`, `fragment`, `headers` and `path`. defualt is `body`, `query` and `fragment`.

```crystal

Usage example:

```crystal
tester.run_check(
  options: SecTester::Options.new(
    smart_scan: true,
    skip_static_parameters: true,
    project_id: "ufNQ9Fo7XFVAsuyGpo7YTf",
    param_locations: ["query", "body"]
  )
)
```

### Choosing the right tests

When configuring the target you can choose which tests to run.
This is done using the `tests:` option.
This option can be a string or an array of strings.

```crystal
  # single test
  tests: "xss"

  # multiple tests
  tests: ["xss", "sqli"]
```

It's also possible to run all tests by using `nil` option. but it is not recommended.
A quick rule of thumb is thinking about the actual technologies used in the target.
So for example, if the target is using SQL Database, you should run the SQLi test.
Otherwise, if the target is using an HTML rendering engine, you should run the XSS test.

All currently available tests are listed in the [tests.cr](src/tests.cr) file

### Integrating into the CI

To integrate this library into the CI you will need to add the `BRIGHT_TOKEN` ENV vars to your CI.
Then add the following to your `github actions` configuration:

```yml
steps:
  - name: Install npm and Repeater
    run: |
      apt update
      apt-get install -y libnode-dev node-gyp libssl-dev
      apt-get install -y nodejs npm
      npm install -g @neuralegion/nexploit-cli --unsafe-perm=true
  - name: Run tests
    env:
      BRIGHT_TOKEN: ${{ secrets.BRIGHT_TOKEN }}
    run: crystal spec
```

### Example Usage

You can see this shard in action at the [Lucky Sec Test](https://github.com/bararchy/lucky_sec_test) repo.
Specifically look at the [Security Flow Specs](https://github.com/bararchy/lucky_sec_test/blob/main/spec/flows/security_spec.cr)

### Use as a CLI

For the purpose of testing the library you can use the following command:

```bash
shards build
bin/sec_tester_cli -t BRIGHT_TOKEN -u https://brokencrystals.com/ # or another target
```

This will run the tests on the target and print the results to the console in a nice table format.

You can use `-h` or `--help` to see the available options.

## Contributing

1. Fork it (<https://github.com/NeuraLegion/sec-tester-cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

* [Bar Hofesh](https://github.com/bararchy) - creator and maintainer
