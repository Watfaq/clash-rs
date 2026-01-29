# Async Service Graceful Shutdown Implementation Guide

## Core Principles

When implementing graceful shutdown for async services, follow these principles:

1. **Use CancellationToken to propagate shutdown signals**: Use `tokio_util::sync::CancellationToken` to propagate cancellation signals to all async tasks
2. **Use tokio::select! to listen for cancellation**: Monitor both business logic and cancellation signals simultaneously in main loops
3. **Ensure proper resource cleanup**: Clean up all resources (connections, sessions, file handles, etc.) before exiting
4. **Log shutdown events**: Explicitly log service shutdown information

## Implementation Patterns

### 1. Basic Structure

```rust
use tokio_util::sync::CancellationToken;

pub struct Service {
    cancel: CancellationToken,
    // ... other fields
}

impl Service {
    pub fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
            // ... initialize other fields
        }
    }

    // Provide a method for external shutdown triggering
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}
```

### 2. Graceful Shutdown in Main Loop

**Correct Example** (reference wind-tuic/src/inbound.rs#L142):

```rust
async fn listen(&self) -> eyre::Result<()> {
    // ... initialization code
    
    loop {
        tokio::select! {
            // First branch: listen for cancellation signal
            _ = self.cancel.cancelled() => {
                info!("Service shutting down gracefully");
                break;
            }
            // Second branch: handle business logic
            Some(item) = receiver.recv() => {
                // Process received item
                if let Err(err) = handle_item(item).await {
                    error!("Failed to handle item: {:?}", err);
                }
            }
        }
    }
    
    // Perform cleanup
    self.cleanup().await?;
    Ok(())
}
```

### 3. Graceful Shutdown in Connection Handling

**Correct Example** (reference wind-tuic/src/inbound.rs#L218-L238):

```rust
async fn handle_connection(
    connection: Connection,
    cancel_token: CancellationToken,
) -> eyre::Result<()> {
    loop {
        tokio::select! {
            // Listen for cancellation signal
            _ = cancel_token.cancelled() => {
                info!("Connection handler received shutdown signal");
                // Gracefully close connection
                connection.close().await?;
                break;
            }
            // Handle incoming streams
            Some(stream) = connection.accept_stream() => {
                let cancel = cancel_token.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(stream, cancel).await {
                        error!("Stream handling error: {:?}", e);
                    }
                });
            }
            // Handle datagrams
            Some(datagram) = connection.read_datagram() => {
                if let Err(e) = handle_datagram(datagram).await {
                    error!("Datagram handling error: {:?}", e);
                }
            }
        }
    }
    Ok(())
}
```

### 4. Propagating Cancellation to Spawned Tasks

```rust
// In main task
let cancel = self.cancel.clone();
tokio::spawn(async move {
    if let Err(e) = worker_task(cancel).await {
        error!("Worker task error: {:?}", e);
    }
});

// In spawned task
async fn worker_task(cancel: CancellationToken) -> eyre::Result<()> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Worker task shutting down");
                break;
            }
            _ = do_work() => {
                // Perform work
            }
        }
    }
    Ok(())
}
```

## Common Mistakes

### ❌ Mistake: Not listening for cancellation signal

```rust
// Wrong: loop cannot be interrupted externally
async fn bad_listen(&self) {
    loop {
        let item = receiver.recv().await;
        handle_item(item).await;
    }
}
```

### ❌ Mistake: Not propagating cancellation to spawned tasks

```rust
// Wrong: spawned task cannot be notified to stop
async fn bad_spawn(&self) {
    tokio::spawn(async move {
        loop {
            // This loop will never stop
            do_work().await;
        }
    });
}
```

### ❌ Mistake: Using Arc<AtomicBool> instead of CancellationToken

```rust
// Not recommended: manual stop signal implementation
let should_stop = Arc::new(AtomicBool::new(false));
loop {
    if should_stop.load(Ordering::Relaxed) {
        break;
    }
    // ...
}
```

**Why**:
- `CancellationToken` provides better async notification mechanism
- `cancelled()` method returns a `Future` that can be used in `select!`
- `AtomicBool` requires polling, which is less efficient

## Best Practices Summary

1. ✅ **Use `CancellationToken`**: As the standard mechanism for shutdown signals
2. ✅ **Use `tokio::select!` in all loops**: Monitor both business logic and cancellation signals
3. ✅ **Clone token to pass to spawned tasks**: `let cancel = self.cancel.clone()`
4. ✅ **Log shutdown events**: Use `info!` or `debug!` to log critical shutdown points
5. ✅ **Clean up resources**: Close connections, release handles, etc. before exiting
6. ✅ **Handle errors**: Properly handle errors even during shutdown process

## Complete Example

```rust
use tokio_util::sync::CancellationToken;
use tracing::{info, error};

pub struct AsyncServer {
    cancel: CancellationToken,
    addr: SocketAddr,
}

impl AsyncServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            cancel: CancellationToken::new(),
            addr,
        }
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("Server listening on {}", self.addr);

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    info!("Server shutting down gracefully");
                    break;
                }
                Ok((socket, addr)) = listener.accept() => {
                    info!("Accepted connection from {}", addr);
                    let cancel = self.cancel.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(socket, cancel).await {
                            error!("Connection error: {:?}", e);
                        }
                    });
                }
            }
        }

        info!("Server stopped");
        Ok(())
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    cancel: CancellationToken,
) -> Result<()> {
    let mut buffer = vec![0u8; 1024];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Connection handler received shutdown signal");
                let _ = socket.shutdown().await;
                break;
            }
            result = socket.read(&mut buffer) => {
                match result {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        // Process data
                        socket.write_all(&buffer[..n]).await?;
                    }
                    Err(e) => {
                        error!("Read error: {:?}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
```

## References

- [tokio_util::sync::CancellationToken documentation](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html)
- [tokio::select! macro documentation](https://docs.rs/tokio/latest/tokio/macro.select.html)
- Reference implementation: [wind-tuic inbound.rs](https://github.com/proxy-rs/wind/blob/6c7ccba003d864631f9c094683f9026792cb5c86/crates/wind-tuic/src/inbound.rs)
