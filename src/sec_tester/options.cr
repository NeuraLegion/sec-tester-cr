module SecTester
  struct Options
    property smart_scan : Bool
    property skip_static_parameters : Bool
    property project_id : String?
    property slow_ep_timeout : Int32
    property crawl : Bool

    def initialize(
      @smart_scan : Bool = true,
      @skip_static_parameters : Bool = true,
      @project_id : String? = nil,
      @slow_ep_timeout : Int32 = 1000,
      @crawl : Bool = false
    )
    end
  end
end
