from websockets.sync.client import connect


def hello():
    with connect("ws://127.1:9090/logs", additional_headers={"Authorization": "Bearer clash-rs"}) as websocket:
        while True:
            message = websocket.recv()
            print(f"Received: {message}")


hello()
