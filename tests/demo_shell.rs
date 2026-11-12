use std::io::Cursor;

use shield::demo_shell::run_with_io;

#[test]
fn menu_actions_call_real_security_engine_stages_and_display_results() {
    let input = Cursor::new("2\n3\n1\nstatus.report\nsummary\n4\n1\n5\n1\n6\n7\n8\n9\n");
    let mut output = Vec::new();

    run_with_io(input, &mut output, true).expect("run interactive demo script");

    let output = String::from_utf8(output).expect("UTF-8 shell output");
    for expected in [
        "[TEST DATA] Added one temporary test device.",
        "DEVICE ID",
        "Signed request #1 created for task status.report.",
        "Authentication successful for device",
        "Authorization approved for task status.report.",
        "First submission: APPROVED",
        "Replay submission: REJECTED",
        "Replay rejection reason:",
        "CATEGORY",
        "--- Complete security simulation ---",
        "Valid trusted request: APPROVED",
        "Authenticated but ungranted task: REJECTED",
        "Replayed valid request: REJECTED",
        "Shield demo closed.",
    ] {
        assert!(
            output.contains(expected),
            "missing output: {expected}\n{output}"
        );
    }
}

#[test]
fn invalid_menu_and_device_selection_are_handled_without_panicking() {
    let input = Cursor::new("0\nnot-a-number\n3\n99\n9\n");
    let mut output = Vec::new();

    run_with_io(input, &mut output, true).expect("invalid input should be handled");

    let output = String::from_utf8(output).expect("UTF-8 shell output");
    assert!(output.contains("Invalid menu choice."));
    assert!(output.contains("Invalid device number. No action was taken."));
    assert!(output.contains("Shield demo closed."));
}
