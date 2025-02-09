require "./errors.cr"

module SecTester
  struct Options
    property? smart_scan : Bool
    property? skip_static_parameters : Bool
    property project_id : String?
    property slow_ep_timeout : Int32?
    property target_timeout : Int32?
    property? crawl : Bool
    property param_locations : Array(String)
    property auth_object_id : String?
    property template_id : String?

    VALID_LOCATIONS = [
      "body",
      "query",
      "fragment",
      "path",
      "headers",
      "artifical-query",
      "artifical-fragment",
    ]

    def initialize(
      @smart_scan : Bool = true,
      @skip_static_parameters : Bool = true,
      @project_id : String? = nil,
      @slow_ep_timeout : Int32? = nil,
      @crawl : Bool = false,
      @param_locations : Array(String) = ["query", "body", "fragment"],
      @auth_object_id : String? = nil,
      @template_id : String? = nil,
      @target_timeout : Int32? = nil,
    )
      raise SecTester::Error.new("Invalid param_locations: #{@param_locations}") unless @param_locations.all? { |l| VALID_LOCATIONS.includes?(l) }
    end
  end
end
