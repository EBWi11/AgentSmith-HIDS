import os
SERVER_IP = os.environ.get("SMITH_CONSOLE_BIND", "127.0.0.1")
SERVER_PORT = os.environ.get("SMITH_CONSOLE_PORT", 5157)
SERVER_LISTEN_NUM = os.environ.get("SMITH_CONSOLE_LISTEN_COUTN", 512)

REDIS_IP = os.environ.get("SMITH_CONSOLE_REDIS_SREVER", "localhost")
REDIS_PORT = os.environ.get("SMITH_CONSOLE_REDIS_PORT", 6379)
