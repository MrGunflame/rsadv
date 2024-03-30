use std::sync::Arc;

use rsadv_control::Request;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};

use crate::State;

const CONTROL_SOCKET_ADDR: &str = "/run/rsadv.sock";

pub async fn control_loop(state: Arc<State>) {
    let socket = UnixListener::bind(CONTROL_SOCKET_ADDR).unwrap();

    loop {
        let (stream, _) = socket.accept().await.unwrap();

        tokio::task::spawn(handle_conn(stream, state.clone()));
    }
}

async fn handle_conn(mut conn: UnixStream, state: Arc<State>) {
    loop {
        let mut buf = [0; 4];

        if let Err(err) = conn.read_exact(&mut buf).await {
            tracing::error!("error serving conn: {:?}", err);
            return;
        }

        let len = u32::from_le_bytes(buf);

        let mut buf = vec![0; std::cmp::min(len as usize, u16::MAX as usize)];
        if let Err(err) = conn.read_exact(&mut buf).await {
            tracing::error!("error serving conn: {:?}", err);
            return;
        }

        let req = match Request::decode(&buf[..]) {
            Ok(req) => req,
            Err(err) => {
                tracing::error!("failed to decode control request: {:?}", err);
                return;
            }
        };

        match req {
            Request::AddPrefix(prefix) => {
                state.prefixes.write().push(crate::Prefix {
                    prefix: prefix.prefix,
                    prefix_length: prefix.prefix_length,
                    preferred_lifetime: prefix.preferred_lifetime,
                    valid_lifetime: prefix.valid_lifetime,
                });

                state.prefixes_changed.notify_one();
            }
        }
    }
}
