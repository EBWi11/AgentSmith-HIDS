import redis
import socket

import setting

sk = socket.socket()
sk.bind((setting.SERVER_IP, setting.SERVER_PORT))
sk.listen(setting.SERVER_LISTEN_NUM)

pool = redis.ConnectionPool(host=setting.REDIS_IP, port=setting.REDIS_PORT, decode_responses=True)
redis_helper = redis.Redis(connection_pool=pool)


def handle_request(conn, ip):
    res = redis_helper.get("HIDS-DETECTIVE-{0}".format(ip))
    if not res:
        redis_helper.set("HIDS-DETECTIVE-{0}".format(ip), 1, ex=1200)
        conn.sendall("ListeningSockets;RPMList;SystemUser;CrontabList;\n")
    else:
        conn.sendall(";\n")


while True:
    conn, addr = sk.accept()
    client_data = conn.recv(256)
    if client_data:
        tmp = client_data.split("|")
        redis_helper.delete("HIDSHOST-{0}".format(tmp[0]))
        redis_helper.set("HIDSHOST-{0}".format(tmp[0]), 1, ex=35)
        handle_request(conn, tmp[0])
        try:
            conn.close()
        except:
            pass
