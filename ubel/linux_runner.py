#!/usr/bin/env python3

import subprocess
import shutil
import distro
import json,os
import sys

class Linux_Manager:

    @staticmethod
    def command_exists(cmd):
        return shutil.which(cmd) is not None


    @staticmethod
    def run_command(cmd):
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"[!] Command failed: {' '.join(cmd)}", file=sys.stderr)
            print(e.stderr, file=sys.stderr)
            return ""


    @staticmethod
    def get_os_info():
        info = {
            "id": distro.id().replace(" ",""),
            "name": distro.name(),
            "version": distro.version(),
            "like": distro.like(),
            "package_manager":Linux_Manager.get_pkg_manager(),
            "info": distro.info()
        }

        # Try /etc/os-release (most reliable)
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.rstrip().split("=", 1)
                        info[k.lower()] = v.strip('"')
        except FileNotFoundError:
            pass

        return info

    @staticmethod
    def list_dpkg_packages():
        os_info=Linux_Manager.get_os_info()
        output = Linux_Manager.run_command(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
        packages = []
        for line in output.splitlines():
            name, version = line.split("\t", 1)
            packages.append({
                "name": name,
                "version": version,
                "type": "application",
                "ecosystem": os_info["id"]})
        return packages


    @staticmethod
    def list_rpm_packages():
        os_info=Linux_Manager.get_os_info()
        output = Linux_Manager.run_command(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        packages = []
        for line in output.splitlines():
            name, version = line.split("\t", 1)
            packages.append({
                "name": name, 
                "version": version,
                "type": "application",
                "ecosystem": os_info["id"]})
        return packages


    @staticmethod
    def list_pacman_packages():
        os_info=Linux_Manager.get_os_info()
        output = Linux_Manager.run_command(["pacman", "-Q"])
        packages = []
        for line in output.splitlines():
            name, version = line.split(" ", 1)
            packages.append({
                "name": name, 
                "version": version,
                "type": "application",
                "ecosystem": os_info["id"]})
        return packages


    @staticmethod
    def list_apk_packages():
        output = Linux_Manager.run_command(["apk", "info", "-v"])
        packages = []
        for line in output.splitlines():
            # example: musl-1.2.4-r1
            if "-" in line:
                name, version = line.rsplit("-", 1)
                packages.append({
                    "name": name, 
                    "version": version,
                    "type": "application",
                    "ecosystem": Linux_Manager.get_os_info()["id"]})
        return packages

    @staticmethod
    def get_pkg_manager():
        for item in ["apt","apt-get","dnf","yum"]:
            if Linux_Manager.command_exists(item):
                return item

    @staticmethod
    def detect_and_list_packages():
        if Linux_Manager.command_exists("dpkg-query"):
            return Linux_Manager.list_dpkg_packages()

        if Linux_Manager.command_exists("rpm"):
            return Linux_Manager.list_rpm_packages()

        if Linux_Manager.command_exists("pacman"):
            return Linux_Manager.list_pacman_packages()

        if Linux_Manager.command_exists("apk"):
            return Linux_Manager.list_apk_packages()

        raise RuntimeError("Unsupported Linux distribution or unknown package manager")

    @staticmethod
    def package_to_purl(os_info,package, version):
        os_id=os_info["id"].replace(" ","")
        pkg_manager=os_info["package_manager"]
        if pkg_manager in ["apt","apt-get"]:
             if "ubuntu" in os_id.lower() or "ubuntu" in os_info.get("like","").lower():
                return f'pkg:deb/ubuntu/{package}@{version}' 
             else:
                return f'pkg:deb/debian/{package}@{version}'
        if "almalinux" in os_id.lower():
            return f'pkg:rpm/almalinux/{package}@{version}'
        if "redhat" in os_id.lower():
            return f'pkg:rpm/redhat/{package}@{version}'
        if "alpaquita" in os_id.lower():
            return f'pkg:apk/alpaquita/{package}@{version}'
        if "rocky" in os_id.lower():
            return f'pkg:rpm/rocky-linux/{package}@{version}'
        if "alpine" in os_id.lower():
            return f'pkg:apk/alpine/{package}@{version}'
        raise Exception("Unsupported Linux distribution.")

    @staticmethod
    def get_linux_packages():
        packages=Linux_Manager.detect_and_list_packages()
        system_info=Linux_Manager.get_os_info()
        purls = [Linux_Manager.package_to_purl(system_info,pkg["name"],pkg["version"]) for pkg in packages]
        kernal_version=os.uname().release
        pkg_manager=system_info["package_manager"]
        if pkg_manager in ["apt","apt-get"]:
            purls.append(Linux_Manager.package_to_purl(system_info,"linux",kernal_version))
        return purls

    @staticmethod
    def resolve_packages(packages):
        """
        Simulate dependency resolution and return:
        [
            {"name": "...", "version": "..."},
            ...
        ]
        """

        if isinstance(packages, str):
            packages = [packages]
        
        os_info=Linux_Manager.get_os_info()

        pm = Linux_Manager.get_pkg_manager()
        resolved = []

        # -----------------------------
        # APT (Debian / Ubuntu)
        # -----------------------------
        if pm in ["apt", "apt-get"]:

            cmd = ["apt-get", "-s", "--no-install-recommends", "install"] + packages
            output = Linux_Manager.run_command(cmd)

            # Example line:
            # Inst curl (7.88.1-10ubuntu1 Ubuntu:22.04/jammy [amd64])
            import re
            pattern = re.compile(r"^Inst\s+(\S+)\s+\(([^ ]+)")

            for line in output.splitlines():
                match = pattern.search(line.strip())
                if match:
                    resolved.append({
                        "name": match.group(1),
                        "version": match.group(2),
                        "type": "application",
                        "ecosystem": os_info["id"] 
                    })

            return resolved

        # -----------------------------
        # DNF (RHEL 8+, AlmaLinux)
        # -----------------------------
        if pm == "dnf":

            cmd = ["dnf", "install", "--assumeno"] + packages
            output = Linux_Manager.run_command(cmd)

            capture = False

            for line in output.splitlines():

                line = line.strip()

                # Start of transaction summary
                if line.startswith("Installing:"):
                    capture = True
                    continue

                if capture:
                    if not line:
                        break

                    parts = line.split()
                    if len(parts) >= 2:
                        name_arch = parts[0]
                        version = parts[1]
                        name = name_arch.split(".")[0]

                        resolved.append({
                            "name": name,
                            "version": version,
                            "type": "application",
                            "ecosystem": os_info["id"]
                        })

            return resolved

        # -----------------------------
        # YUM (RHEL 7)
        # -----------------------------
        if pm == "yum":

            cmd = ["yum", "install", "--assumeno"] + packages
            output = Linux_Manager.run_command(cmd)

            capture = False

            for line in output.splitlines():

                line = line.strip()

                if line.startswith("Installing:"):
                    capture = True
                    continue

                if capture:
                    if not line:
                        break

                    parts = line.split()
                    if len(parts) >= 2:
                        name_arch = parts[0]
                        version = parts[1]
                        name = name_arch.split(".")[0]
                        resolved.append({
                            "name": name,
                            "version": version,
                            "type": "application",
                            "ecosystem": os_info["id"]
                        })
            return resolved

        raise RuntimeError("Unsupported package manager for resolution")

    @staticmethod
    def get_packages_purls(packages):
        packages=Linux_Manager.resolve_packages(packages)
        system_info=Linux_Manager.get_os_info()
        return [Linux_Manager.package_to_purl(system_info,pkg["name"],pkg["version"]) for pkg in packages]



    @staticmethod
    def run_real_install(packages_list):
        pmg=Linux_Manager.get_os_info()["package_manager"]
        packages=[]
        if pmg in ["apt","apt-get"]:
            packages+=[f"{item[0]}={item[1]}" for item in packages_list]
        else:
            packages+=[f"{item[0]}-{item[1]}" for item in packages_list]
        cmd = ["sudo", pmg , "install","-y"]+packages
        return subprocess.run(cmd)