import os
import socket
import sys
import threading
import time

import zmq

TEST_TIMEOUT = 15 * 60


def listen_logs(run_id):
	print("Listening for logs...")
	ctx = zmq.Context()
	build_sub = ctx.socket(zmq.SUB)
	build_sub.setsockopt_string(zmq.PLAIN_USERNAME, "user")
	build_sub.setsockopt_string(zmq.PLAIN_PASSWORD, os.environ["AUTH_TOKEN"])
	build_sub.setsockopt_string(zmq.SUBSCRIBE, f"{run_id}-build")
	build_sub.connect(f"tcp://{os.environ['IP']}:{os.environ['BUILD_LOG_PORT']}")

	test_sub = ctx.socket(zmq.SUB)
	test_sub.setsockopt_string(zmq.PLAIN_USERNAME, "user")
	test_sub.setsockopt_string(zmq.PLAIN_PASSWORD, os.environ["AUTH_TOKEN"])
	test_sub.setsockopt_string(zmq.SUBSCRIBE, f"{run_id}-test")
	test_sub.connect(f"tcp://{os.environ['IP']}:{os.environ['TEST_LOG_PORT']}")
	print("Connected to log server")

	poller = zmq.Poller()
	poller.register(build_sub, zmq.POLLIN)
	poller.register(test_sub, zmq.POLLIN)

	while True:
		socks = dict(poller.poll())
		for sock in socks:
			if socks[sock] == zmq.POLLIN:
				resp = sock.recv_multipart()
				if len(resp) != 2:
					print("Invalid pub message", resp)
				else:
					_, msg = resp
					print(msg.decode(), end="")


def main():
	if len(sys.argv) < 5:
		# ${{ github.sha }} ${{ github.actor }} ${{ github.event.head_commit.message }} ${{ github.run_id }}
		print("Usage: python3 client_test hash author name run_id branch")
		sys.exit(1)

	threading.Thread(target=listen_logs, args=(sys.argv[4],), daemon=True).start()

	conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# enable keepalive
	conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
	# start sending probes after x seconds
	conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
	# send probe every x seconds
	conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
	# close connection after x fails
	conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

	conn.settimeout(TEST_TIMEOUT)

	conn.connect((os.environ["IP"], int(os.environ["BUILD_PORT"])))
	print("Connected to build server")

	conn.send(os.environ["AUTH_TOKEN"].encode())

	ack = conn.recv(1024).decode()

	if not ack or "Invalid" in ack:
		print("Connection error")
		sys.exit(1)

	print("Authenticated with build server")

	conn.send(
		f"{sys.argv[1]}\x1b{sys.argv[2]}\x1b{sys.argv[3]}\x1b{sys.argv[4]}\x1b{sys.argv[5]}".encode()
	)
	while True:
		try:
			data = conn.recv(1024)
		except TimeoutError:
			print("Process timed out")
			sys.exit(1)

		if not data:
			print("Process exited without error code")
			sys.exit(1)
		line = data.decode(errors="ignore")
		try:
			exit_code = int(line)
			print(f"Process exited with code {exit_code}")
			time.sleep(2)
			sys.exit(exit_code)
		except ValueError:
			pass


if __name__ == "__main__":
	main()
