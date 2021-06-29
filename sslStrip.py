import os

interface = "enp0s9"


class SSLStrip:

    def start(self):
        try:
            print "[*] Starting SSLStrip"
            os.system('sslstrip')
        except KeyboardInterrupt:
            print "[*] Stopped SSL Strip"