import redis
import socket

import smith_console.setting as setting

pool = redis.ConnectionPool(host=setting.REDIS_IP,
                            port=setting.REDIS_PORT, decode_responses=True)
redis_helper = redis.Redis(connection_pool=pool)


def handle_request(conn, ip):
    res = redis_helper.get("HIDS-DETECTIVE-{0}".format(ip))
    if not res:
        redis_helper.set("HIDS-DETECTIVE-{0}".format(ip), 1, ex=1200)
        conn.sendall(b"ListeningSockets;RPMList;SystemUser;CrontabList;\n")
    else:
        conn.sendall(b";\n")


def data_handler(conn, tmp):

    redis_helper.delete("HIDSHOST-{0}".format(tmp[0]))
    redis_helper.set("HIDSHOST-{0}".format(tmp[0]), 1, ex=35)
    handle_request(conn, tmp[0])


def server_start():
    sk = socket.socket()
    sk.bind((setting.SERVER_IP, setting.SERVER_PORT))
    sk.listen(setting.SERVER_LISTEN_NUM)
    try:
        while True:
            conn, addr = sk.accept()
            client_data = conn.recv(256)
            if client_data:
                try:
                    tmp = client_data.decode("utf-8").split("|")
                    data_handler(conn, tmp)
                except Exception as e:
                    conn.close()
                    print("error: {} {}".format(e, client_data))
                    continue
                try:
                    conn.close()
                except:
                    pass
    except Exception as e:
        print("closing socket: {}".format(e))
        sk.closee()
        exit(1)


if __name__ == "__main__":
    server_start()
