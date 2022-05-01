# sec-tester-cr

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

To use the library you will first need to

1. Register for an account at [signup](https://app.neuralegion.com/signup)
2. install the [nexploit-cli](https://www.npmjs.com/package/@neuralegion/nexploit-cli) utility
3. Generate an API key from your [UI](https://docs.brightsec.com/docs/manage-your-personal-account#manage-your-personal-api-keys-authentication-tokens)
4. The preferred approach is to setup your API-Key as ENV var `NEXPLOIT_TOKEN` for API key.

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

* PRO-TIP: configuring the response information is very important for the scanner to work properly. and can decrease scan times and improve the accuracy of the scan.

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

The `severity_threshold` is a `:low`, `:medium` or `:high` value. it allows you to not fail the build if the severity is lower than the threshold.

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

Usage example:

```crystal
tester.run_check(
  options: SecTester::Options.new(
    smart_scan: true,
    skip_static_parameters: true,
    project_id: "ufNQ9Fo7XFVAsuyGpo7YTf"
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

All currently available tests are listed below:

```json
[
  "jwt",
  "broken_saml_auth",
  "brute_force_login",
  "common_files",
  "cookie_security",
  "csrf",
  "xss",
  "default_login_location",
  "directory_listing",
  "dom_xss",
  "email_injection",
  "file_upload",
  "full_path_disclosure",
  "header_security",
  "html_injection",
  "http_method_fuzzing",
  "improper_asset_management",
  "insecure_tls_configuration",
  "ldapi",
  "lfi",
  "nosql",
  "open_buckets",
  "open_database",
  "osi",
  "proto_pollution",
  "rfi",
  "secret_tokens",
  "ssti",
  "server_side_js_injection",
  "ssrf",
  "sqli",
  "unvalidated_redirect",
  "version_control_systems",
  "wordpress",
  "xxe",
  "xpathi",
  "business_constraint_bypass",
  "date_manipulation",
  "id_enumeration",
  "mass_assignment",
  "retire_js"
]
```

### Integrating into the CI

To integrate this library into the CI you will need to add the `NEXPLOIT_TOKEN` ENV vars to your CI.
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
      NEXPLOIT_TOKEN: ${{ secrets.NEXPLOIT_TOKEN }}
    run: crystal spec
```

### Example Usage

You can see this shard in action at the [Lucky Sec Test](https://github.com/bararchy/lucky_sec_test) repo.
Specifically look at the [Security Flow Specs](https://github.com/bararchy/lucky_sec_test/blob/main/spec/flows/security_spec.cr)

## Contributing

1. Fork it (<https://github.com/NeuraLegion/sec-tester-cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

* [Bar Hofesh](https://github.com/bararchy) - creator and maintainer
