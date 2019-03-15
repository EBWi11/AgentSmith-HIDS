import random
import re
import redis
import signal
from IPy import IP
from pyfiglet import Figlet

import cprint
import setting

signal.signal(signal.SIGINT, signal.default_int_handler)
pool = redis.ConnectionPool(host=setting.REDIS_IP, port=setting.REDIS_PORT, decode_responses=True)
redis_helper = redis.Redis(connection_pool=pool)

random_font_list = ["ogre", "small", "slant", "script", "larry3d", "eftifont", "drpepper", "doom", "chunky"]

if __name__ == "__main__":
    try:
        random_font = random_font_list[random.randint(0, len(random_font_list) - 1)]
        f = Figlet(font=random_font, width=150)
        cprint.cprintln(f.renderText('Agent Smith HIDS'), "bold", "yellow")
        cprint.cprintln('\t\t\t\t\t\t\t\t\t-- By E_Bwill\n', "underline", "cyan")
        all_host = redis_helper.keys("HIDSHOST-*")
        cprint.cprintln('[ {0} HIDS Online ]'.format(len(all_host)), "invert", "cyan")
        while (True):
            cmd = raw_input(">>> ")
            cmd = cmd.strip().lower()
            if cmd == "exit":
                print("Bye.")
                exit(0)
            elif cmd.find("::") > -1 or cmd.find(".") > -1:
                try:
                    IP(cmd)
                    tmp_res = redis_helper.get("HIDSHOST-{0}".format(cmd))
                    if tmp_res:
                        cprint.cprintln("Online", "mormal", "green")
                    else:
                        cprint.cprintln("Not Found", "mormal", "red")
                    continue
                except:
                    pass
            if cmd.startswith("list"):
                i = 1
                cmd = re.sub(r"\s+", " ", cmd)
                all_host = None
                if len(cmd.split(" ")) > 1:
                    all_host = redis_helper.keys("HIDSHOST-{0}*".format(cmd.split(" ")[1]))
                else:
                    all_host = redis_helper.keys("HIDSHOST-*")
                for h in all_host:
                    cprint.cprint("{0}:".format(i), "mormal", "green")
                    print(" {0}".format(h.split("-")[1]))
                    i = i + 1
                if i == 1:
                    cprint.cprintln("Not Found", "mormal", "red")
            elif cmd == "count":
                all_host = redis_helper.keys("HIDSHOST-*")
                cprint.cprint("Online Hosts: ", "mormal", "green")
                print("{0}".format(len(all_host)))
            elif cmd == "help":
                cprint.cprint("list: ", "mormal", "green")
                print("Show all hids online host.")
                cprint.cprint("count: ", "mormal", "green")
                print("Get onlion HIDS count.")
                cprint.cprint("some ip: ", "mormal", "green")
                print("You can enter some ip for search this host HIDS situation.")
                cprint.cprint("exit: ", "mormal", "green")
                print("Exit HIDS console.")
            else:
                cprint.cprintln("Undefined command: \"{0}\". Try `help`.".format(cmd), "mormal", "red")
    except KeyboardInterrupt:
        print("\nBye.")
        exit(0)
