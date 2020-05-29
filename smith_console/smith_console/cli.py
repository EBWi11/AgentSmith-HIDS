def console():
    from smith_console.smith import smith_main
    smith_main()


def server():
    from smith_console.heartbeat_server import server_start
    server_start()

