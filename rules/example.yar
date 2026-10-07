rule ExampleSuspicious {
    meta:
        description = "Example rule for testing"
        author = "YARA Scanner"
        severity = "low"
        hash = "md5:example"
    
    strings:
        $test = "test"
    
    condition:
        $test
}
