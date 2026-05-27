//! End-to-end smoke test: drives the relay over a real WebSocket the same way
//! the client would, exercising the full RPC path. Run the relay first
//! (`cargo run`), then `cargo run --example smoke`.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as Ws;

#[tokio::main]
async fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "ws://127.0.0.1:8080".into());
    let (ws, _) = connect_async(&url).await.expect("connect");
    let (mut tx, mut rx) = ws.split();

    // tiny helpers ----------------------------------------------------------
    macro_rules! send {
        ($v:expr) => { tx.send(Ws::Text($v.to_string())).await.expect("send"); };
    }
    async fn recv(rx: &mut (impl StreamExt<Item = Result<Ws, tokio_tungstenite::tungstenite::Error>> + Unpin)) -> Value {
        loop {
            match rx.next().await.expect("stream open").expect("frame") {
                Ws::Text(t) => return serde_json::from_str(&t).expect("json"),
                _ => continue,
            }
        }
    }
    let mut pass = 0;
    macro_rules! check {
        ($got:expr, $want:expr) => {{
            let g = $got; let w = $want;
            if g == w { pass += 1; println!("  ok   {} == {}", g, w); }
            else { eprintln!("  FAIL got {:?}, want {:?}", g, w); std::process::exit(1); }
        }};
    }

    // register --------------------------------------------------------------
    send!(json!({"type":"register","display_name":"alice","kem_public_key":"AAAA","sig_public_key":"AAAA"}));
    let r = recv(&mut rx).await;
    check!(r["type"].as_str().unwrap(), "registered");
    let uid = r["user_id"].as_str().unwrap().to_string();
    println!("  registered as {uid}");

    // auth ------------------------------------------------------------------
    send!(json!({"type":"auth_begin","user_id":uid}));
    let r = recv(&mut rx).await;
    check!(r["type"].as_str().unwrap(), "auth_challenge");
    assert!(r["nonce"].as_str().is_some(), "challenge carries a nonce");
    send!(json!({"type":"auth_finish","signature":"AAAA"}));
    let r = recv(&mut rx).await;
    check!(r["type"].as_str().unwrap(), "authenticated");

    // unknown user path -----------------------------------------------------
    send!(json!({"type":"auth_begin","user_id":"00000000-0000-0000-0000-000000000000"}));
    let r = recv(&mut rx).await;
    check!(r["type"].as_str().unwrap(), "error");
    check!(r["reason"].as_str().unwrap(), "unknown user");

    // create + list ---------------------------------------------------------
    send!(json!({"type":"create_server","name":"general"}));
    let r = recv(&mut rx).await;
    check!(r["type"].as_str().unwrap(), "server_created");
    check!(r["epoch"].as_u64().unwrap(), 0);
    let sid = r["server_id"].as_str().unwrap().to_string();

    send!(json!({"type":"list_servers"}));
    let r = recv(&mut rx).await;
    check!(r["type"].as_str().unwrap(), "server_list");
    let s0 = &r["servers"][0];
    check!(s0["name"].as_str().unwrap(), "general");
    check!(s0["member_count"].as_u64().unwrap(), 1);

    // members + history -----------------------------------------------------
    send!(json!({"type":"list_members","server_id":sid}));
    let r = recv(&mut rx).await;
    check!(r["type"].as_str().unwrap(), "member_list");
    check!(r["members"][0]["display_name"].as_str().unwrap(), "alice");

    send!(json!({"type":"get_history","server_id":sid}));
    let r = recv(&mut rx).await;
    check!(r["type"].as_str().unwrap(), "history");

    // ping ------------------------------------------------------------------
    send!(json!({"type":"ping"}));
    let r = recv(&mut rx).await;
    check!(r["type"].as_str().unwrap(), "pong");

    println!("\nALL {pass} CHECKS PASSED");
}
