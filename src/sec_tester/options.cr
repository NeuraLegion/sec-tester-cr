module SecTester
  struct Options
    property smart_scan : Bool
    property skip_static_parameters : Bool
    property project_id : String?
    property slow_ep_timeout : Int32
    property crawl : Bool
    property param_locations : Array(String)

    VALID_LOCATIONS = [
      "body",
      "query",
      "fragment",
      "path",
      "headers",
      "artificial-query",
      "artificial-fragment",
    ]

    def initialize(
      @smart_scan : Bool = true,
      @skip_static_parameters : Bool = true,
      @project_id : String? = nil,
      @slow_ep_timeout : Int32 = 1000,
      @crawl : Bool = false,
      @param_locations : Array(String) = ["query", "body", "fragment"]
    )
      raise SecTester::Error.new("Invalid param_locations: #{@param_locations}") unless @param_locations.all? { |l| VALID_LOCATIONS.includes?(l) }
    end
  end
end
