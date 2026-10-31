use kabuk_proto::id::Bytes;
use kabuk_proto::relay::{REGISTER_CONTEXT, register_message};

#[test]
fn register_message_is_context_then_challenge() {
	let message = register_message(&Bytes([7; 32]));
	assert_eq!(&message[..24], REGISTER_CONTEXT);
	assert_eq!(&message[24..], &[7; 32]);
}
