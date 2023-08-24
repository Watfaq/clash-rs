from websockets.sync.client import connect


def hello():
    with connect("ws://127.1:6170/logs") as websocket:
        while True:
            message = websocket.recv()
            print(f"Received: {message}")


hello()
