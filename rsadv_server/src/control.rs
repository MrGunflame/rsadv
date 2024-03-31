use std::sync::Arc;

use rsadv_control::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::State;

const CONTROL_SOCKET_ADDR: &str = "/run/rsadv.sock";

pub async fn control_loop(state: Arc<State>) {
    // connect will return ECONNREFUSED if the socket file exists but
    // no one is listening. In that case we take over the socket
    // (e.g. becuase the previous process crashed without removing the socket).
    if UnixStream::connect(CONTROL_SOCKET_ADDR).await.is_ok() {
        panic!("socket already in use");
    }

    std::fs::remove_file(CONTROL_SOCKET_ADDR).unwrap();

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
                state.prefixes.write().insert(
                    prefix.prefix,
                    crate::Prefix {
                        prefix: prefix.prefix,
                        prefix_length: prefix.prefix_length,
                        preferred_lifetime: prefix.preferred_lifetime,
                        valid_lifetime: prefix.valid_lifetime,
                    },
                );

                state.prefixes_changed.notify_one();
            }
            Request::RemovePrefix(prefix) => {
                state.prefixes.write().remove(&prefix.prefix);
                state.prefixes_changed.notify_one();
            }
        }

        let resp = Response::Ok;

        let mut buf = Vec::new();
        resp.encode(&mut buf);

        let mut buf_with_len = Vec::new();
        buf_with_len.extend((buf.len() as u32).to_le_bytes());
        buf_with_len.extend(&buf);

        if let Err(err) = conn.write_all(&buf_with_len).await {
            tracing::error!("error serving conn: {:?}", err);
            return;
        }
    }
}
