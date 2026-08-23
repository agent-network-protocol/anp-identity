#[test]
fn private_key_types_are_not_public() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/private_key_api.rs");
    cases.compile_fail("tests/compile_fail/engine_api.rs");
}
