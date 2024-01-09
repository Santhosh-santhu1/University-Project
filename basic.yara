rule ExampleRule {
    strings:
        $magic_string = "abc"
    condition:
        $magic_string
}