#[test]
fn welcome_message_is_available_from_the_library() {
    assert_eq!(shield::welcome_message(), "Welcome to Shield");
}
