extern crate yubihsm_client;

#[cfg(feature = "mockhsm")]
use std::thread;

use yubihsm_client::{Connector, KeyId, Session, SessionId};
#[cfg(feature = "mockhsm")]
use yubihsm_client::mockhsm::MockHSM;

/// Test against the real yubihsm-connector
#[cfg(not(feature = "mockhsm"))]
const YUBIHSM_ADDR: &str = "127.0.0.1:12345";

// TODO: pick an open port automatically
#[cfg(feature = "mockhsm")]
const MOCKHSM_ADDR: &str = "127.0.0.1:54321";

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: KeyId = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

#[cfg(not(feature = "mockhsm"))]
#[test]
fn yubihsm_integration_test() {
    let conn = Connector::open(&format!("http://{}", YUBIHSM_ADDR))
        .unwrap_or_else(|err| panic!("cannot open connection to yubihsm-connector: {:?}", err));

    let mut session = conn.create_session_from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
        .unwrap_or_else(|err| panic!("error creating session: {:?}", err));

    assert_eq!(session.id(), SessionId::new(0).unwrap());
    echo_test(&mut session);
}

#[cfg(feature = "mockhsm")]
fn start_mockhsm(num_requests: usize) -> thread::JoinHandle<()> {
    thread::spawn(move || MockHSM::new(MOCKHSM_ADDR).unwrap().run(num_requests))
}

#[cfg(feature = "mockhsm")]
#[test]
fn mockhsm_integration_test() {
    let num_requests = 4;
    let mockhsm_thread = start_mockhsm(num_requests);

    let conn = Connector::open(&format!("http://{}", MOCKHSM_ADDR))
        .unwrap_or_else(|err| panic!("cannot open connection to mockhsm: {:?}", err));

    let mut session = conn.create_session_from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
        .unwrap_or_else(|err| panic!("error creating session: {:?}", err));

    assert_eq!(session.id(), SessionId::new(0).unwrap());
    echo_test(&mut session);

    mockhsm_thread.join().unwrap();
}

// Send a simple echo request
fn echo_test(session: &mut Session) {
    let message = b"Hello, world!";
    let echo_result = session
        .echo(message)
        .unwrap_or_else(|err| panic!("error sending echo: {:?}", err));

    assert_eq!(&message[..], &echo_result[..]);
}