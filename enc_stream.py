import argparse
import sys

from enc_stream_server import run_server
from enc_stream_client import capture_and_send


def main():
    parser = argparse.ArgumentParser(description="Encrypted video stream (client/server)")
    parser.add_argument("--role", choices=["server", "client"], required=True, help="Run as server or client")
    parser.add_argument("--host", default="0.0.0.0", help="Server bind address (server) or server host to connect to (client)")
    parser.add_argument("--port", type=int, default=6000, help="TCP port")
    parser.add_argument("--secret", default="secret.txt", help="Path to secret file")
    parser.add_argument("--quality", type=int, default=70, help="JPEG quality for client (0-100)")
    parser.add_argument("--fps", type=int, default=15, help="Target FPS for client")

    args = parser.parse_args()

    if args.role == "server":
        print(f"Starting server on {args.host}:{args.port}, secret={args.secret}")
        run_server(host=args.host, port=args.port, secret_path=args.secret)
    else:
        # client
        server_host = args.host if args.host != "0.0.0.0" else "127.0.0.1"
        print(f"Starting client to {server_host}:{args.port}, secret={args.secret}, quality={args.quality}, fps={args.fps}")
        try:
            capture_and_send(server_host=server_host, server_port=args.port, secret_path=args.secret, quality=args.quality, target_fps=args.fps)
        except KeyboardInterrupt:
            print("Client interrupted")


if __name__ == "__main__":
    main()
