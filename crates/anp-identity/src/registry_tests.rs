use super::RootCapabilityState;

#[test]
fn root_capability_default_and_wire_values_remain_compatible() {
    assert_eq!(RootCapabilityState::default(), RootCapabilityState::Active);
    for (state, wire) in [
        (RootCapabilityState::Absent, "\"absent\""),
        (RootCapabilityState::Pending, "\"pending\""),
        (RootCapabilityState::Active, "\"active\""),
    ] {
        assert_eq!(serde_json::to_string(&state).unwrap(), wire);
        assert_eq!(
            serde_json::from_str::<RootCapabilityState>(wire).unwrap(),
            state
        );
    }
}
