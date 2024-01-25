require "json"

module SecTester
  struct Issue
    include JSON::Serializable

    getter name : String
    getter severity : String
    getter details : String
    getter remedy : String
    getter comments : Array(Comment)
    getter resources : Array(String)
    getter id : String
    getter cwe : String

    @[JSON::Field(emit_null: true)]
    getter cvss : String?

    @[JSON::Field(key: "scanId")]
    property scan_id : String

    def issue_url : String
      "/scans/#{scan_id}/issues/#{id}"
    end

    struct Comment
      include JSON::Serializable
      getter headline : String
      getter text : String
    end
  end
end
