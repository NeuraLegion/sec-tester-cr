module SecTester
  struct Options
    property smart_scan : Bool
    property skip_static_parameters : Bool
    property project_id : String?

    def initialize(
      @smart_scan : Bool = true,
      @skip_static_parameters : Bool = true,
      @project_id : String? = nil
    )
    end
  end
end
