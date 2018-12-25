import redis
import socket

import setting

sk = socket.socket()
sk.bind((setting.SERVER_IP, setting.SERVER_PORT))
sk.listen(setting.SERVER_LISTEN_NUM)

pool = redis.ConnectionPool(host=setting.REDIS_IP, port=setting.REDIS_PORT, decode_responses=True)
redis_helper = redis.Redis(connection_pool=pool)

while True:
    conn, addr = sk.accept()
    client_data = conn.recv(128)
    if client_data:
        tmp = client_data.split("|")
        redis_helper.delete("HIDSHOST-{0}".format(tmp[0]))
        redis_helper.set("HIDSHOST-{0}".format(tmp[0]), 1, ex=65)
