pub async fn get_connections_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<CtrlState>>,
    query: Query<GetConnectionsQuery>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let interval = query.interval.unwrap_or(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval));

        loop {
            interval.tick().await;
            let snapshot = state.statistics_manager.snapshot().await;

            let body = serde_json::to_string(&snapshot)?;

            socket.send(Message::Text(body.into())).await?;
        }
        #[allow(unused)]
        anyhow::Ok(())
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await.unwrap_or_else(|e| {
            debug!("ws connection closed with error: {}", e);
        });
    })
}


#[derive(Serialize)]
struct TrafficResponse {
    up: u64,
    down: u64,
}

pub async fn handle(
    ws: WebSocketUpgrade,
    State(state): State<Arc<CtrlState>>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let stats = state.statistics_manager.clone();
        loop {
            interval.tick().await;

            let (up, down) = stats.now();
            let res = TrafficResponse { up, down };

            let body = serde_json::to_string(&res)?;

            socket.send(Message::Text(body.into())).await?;
        }
        #[allow(unused)]
        anyhow::Ok(())
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await.unwrap_or_else(|e| {
            debug!("ws connection closed with error: {}", e);
        });
    })
}


pub async fn handle_memory(
    ws: WebSocketUpgrade,
    State(state): State<Arc<CtrlState>>,
    query: Query<GetMemoryQuery>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let interval = query.interval.unwrap_or(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval));

        loop {
            interval.tick().await;
            let snapshot = GetMemoryResponse {
                inuse: state.statistics_manager.memory_usage(),
                oslimit: 0,
            };

            let body = serde_json::to_string(&snapshot)?;

            socket.send(Message::Text(body.into())).await?;
        }
        #[allow(unused)]
        anyhow::Ok(())
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await.unwrap_or_else(|e| {
            debug!("ws connection closed with error: {}", e);
        });
    })
}


pub async fn handle_log(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<CtrlState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {} with {}", e, addr);
    })
    .on_upgrade(move |mut socket| async move {
        let mut rx = state.log_source_tx.subscribe();
        while let Ok(evt) = rx.recv().await {
            let res = serde_json::to_vec(&evt).unwrap();

            if let Err(e) = socket
                .send(Message::Text(String::from_utf8(res).unwrap().into()))
                .await
            {
                warn!("ws send error: {}", e);
                break;
            }
        }
    })
}
