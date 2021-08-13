
import requests
import os
import subprocess, sys
import datetime
from stat import S_IREAD, S_IRGRP, S_IROTH
from shutil import copy2

import argparse
import textwrap
from sortedcontainers import SortedSet


linux_host_path = "/etc/host"
windows_host_path = "c:\\windows\\system32\\drivers\\etc\\hosts"


class Host:
    def __init__(self, blocklist_count=0):
        self.blocklist_count = blocklist_count

    def generate_host(self):
        self.blocklist_count = 0
        dir = os.getcwd()
        filename = os.path.join(dir, 'hosts')
        redirect_url = '0.0.0.0'

        print("[INFO] Disabling and stoping Dnscache service")

        # BELOW Commands Requires Administration permissions.
        # Prevent Windows Defender from blocking the hosts file.
        # See: https://www.bleepingcomputer.com/news/microsoft/windows-10-hosts-file-blocking-telemetry-is-now-flagged-as-a-risk/
        p = subprocess.Popen(f'powershell.exe Add-MpPreference -ExclusionPath {windows_host_path}', stdout=sys.stdout)
        p.communicate()

        # Disable and stop the Dnscache service.
        p = subprocess.Popen(f"powershell.exe Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\Dnscache'\
               -Name 'Start' -Value 4", stdout=sys.stdout)
        p.communicate()


        urls = [
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/adaway.org/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/adblock-nocoin-list/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/adguard-cname-trackers/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/adguard-simplified/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/dandelionsprout-nordic/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/digitalside-threat-intel/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-ara/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-bul/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-ces-slk/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-deu/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-fra/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-heb/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-ind/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-ita/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-kor/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-lav/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-lit/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-nld/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-por/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-rus/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-spa/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easylist-zho/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easyprivacy/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/eth-phishing-detect/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/gfrogeye-firstparty-trackers/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/hostsvn/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/kadhosts/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/matomo.org-spammers/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/mitchellkrogza-badd-boyz-hosts/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/pgl.yoyo.org/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/phishing.army/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/socram8888-notonmyshift/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/someonewhocares.org/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/spam404.com/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/stevenblack/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/ublock/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/ublock-abuse/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/ublock-badware/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/ublock-privacy/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/urlhaus/list.txt",
            "https://raw.githubusercontent.com/hectorm/hmirror/master/data/winhelp2002.mvps.org/list.txt",
        ]

        blocklist = SortedSet()

        # TODO Add allowlist and denylist functionality
        allowlist = []

        # Special Domain to check the working of hBlock
        denylist = ['hblock-check.molinero.dev']

        blocklist.update(denylist)

        print("[INFO] Downloading sources")
        for url in urls:
            print(f"* {url}")
            data = requests.get(url)

            data = data.text.splitlines()
            blocklist.update(data)

        self.blocklist_count = len(blocklist)

        header = textwrap.dedent(f"""
            # Generated with:  https://github.com/Arindamghosh01/Host-Ad-blocker
            # Total BlockListed Websites : {self.blocklist_count}

            # BEGIN HEADER
            127.0.0.1       localhost
            255.255.255.255 broadcasthost
            ::1             localhost
            ::1             ip6-localhost ip6-loopback
            fe00::0         ip6-localnet
            ff00::0         ip6-mcastprefix
            ff02::1         ip6-allnodes
            ff02::2         ip6-allrouters
            ff02::3         ip6-allhosts
            # END HEADER
            """
        )

        with open(filename, 'w+') as f:
            f.write(header)


        with open(filename, 'a+') as f:
            f.write("\n# BEGIN BLOCKLIST\n")
            for domain in blocklist:
                f.write(redirect_url + ' ' + domain + '\n')
            f.write("# END BLOCKLIST")

        print(f"\n[INFO] Sanitizing blocklist")
        print(f"[INFO] Applying template")
        print(f"[INFO] {self.blocklist_count} Blocked Domains!")

    def copy_host_file(self):
        src = os.getcwd()+"\\hosts"
        dst = "c:\\windows\\system32\\drivers\\etc"
        copy2(src, dst);

    def create_backup(self):
        src=os.getcwd()
        os.chdir("c:\\windows\\system32\\drivers\\etc")

        if not os.path.isfile("hosts_backup"):
            os.chmod("hosts", S_IREAD|S_IRGRP|S_IROTH)
            backup_name = "hosts_backup"
            os.rename("hosts", backup_name)

        os.chdir(src)

    def cleanup(self):
        os.remove("hosts")

    def restore_default_host(self):
        src=os.getcwd()
        os.chdir("c:\\windows\\system32\\drivers\\etc")

        if os.path.isfile("hosts_backup"):
            os.chmod("hosts", 0o777)
            os.remove("hosts")
            os.chmod("hosts_backup", S_IREAD|S_IRGRP|S_IROTH)
            os.rename("hosts_backup", "hosts")

        os.chdir(src)


def parse_args():
    parser = argparse.ArgumentParser(
            description='Note: This script requires administrative priviliges to work properly.\
            This is a python script that gets a list of domains that serve\
            ads, tracking scripts and malware from multiple sources and creates a hosts\
            file, that prevents your system from connecting to them.')

    parser.add_argument("-r", "--restore", action="store_true",
                        help="Restore to default host file")

    return parser.parse_args()

def main():
    args = parse_args()
    host = Host()

    if args.restore:
        host.restore_default_host()
        print("Your host file is resored to default successfully. ")
    else:
        host.create_backup()
        host.generate_host()
        host.copy_host_file()
        host.cleanup()


if __name__ == "__main__":
    main()
