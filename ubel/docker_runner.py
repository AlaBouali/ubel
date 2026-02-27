import subprocess
import json
import shutil
import sys
import os
import copy

class DockerLinuxInspector:

    @staticmethod
    def run_docker(image, cmd):
        """
        Run a command inside a temporary throwaway container.
        """
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", image] + cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"[!] Docker command failed for image {image}: {' '.join(cmd)}",
                  file=sys.stderr)
            print(e.stderr, file=sys.stderr)
            return ""

    # ----------------------------------------------------------------------
    # OS INFO FROM INSIDE THE DOCKER IMAGE
    # ----------------------------------------------------------------------

    @staticmethod
    def detect_os_info(image):
        """
        Extract OS info by reading /etc/os-release inside the Docker image.
        """
        content = DockerLinuxInspector.run_docker(image, ["cat", "/etc/os-release"])

        info = {
            "id": "",
            "name": "",
            "version": "",
            "like": "",
            "package_manager": None,
            "info": {}
        }

        for line in content.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.lower()] = v.strip('"')

        info["id"] = info.get("id", "").replace(" ", "")
        info["name"] = info.get("name", "")
        info["version"] = info.get("version_id", "")
        info["like"] = info.get("id_like", "")

        info["package_manager"] = DockerLinuxInspector.detect_pkg_manager(image)
        info["info"] = copy.deepcopy(info)

        return info

    # ----------------------------------------------------------------------
    # DETECT PACKAGE MANAGER
    # ----------------------------------------------------------------------

    @staticmethod
    def detect_pkg_manager(image):
        cmds = {
            "dpkg-query": "dpkg",
            "rpm": "rpm",
            "apk": "apk",
            "pacman": "pacman"
        }

        for binname, pm in cmds.items():
            found = DockerLinuxInspector.run_docker(
                image, ["sh", "-c", f"command -v {binname} || true"]
            )
            if found.strip():
                return pm

        raise RuntimeError("Unsupported distribution: no known package manager found")

    # ----------------------------------------------------------------------
    # PACKAGE LISTING (MATCHES YOUR OUTPUT MODEL)
    # ----------------------------------------------------------------------

    @staticmethod
    def list_dpkg_packages(image, os_info):
        output = DockerLinuxInspector.run_docker(
            image,
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]
        )
        pkgs = []
        for line in output.splitlines():
            if "\t" not in line:
                continue
            name, version = line.split("\t", 1)
            pkgs.append({
                "name": name,
                "version": version,
                "type": "application",
                "ecosystem": os_info["id"]
            })
        return pkgs

    @staticmethod
    def list_rpm_packages(image, os_info):
        output = DockerLinuxInspector.run_docker(
            image,
            ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]
        )
        pkgs = []
        for line in output.splitlines():
            if "\t" not in line:
                continue
            name, version = line.split("\t", 1)
            pkgs.append({
                "name": name,
                "version": version,
                "type": "application",
                "ecosystem": os_info["id"]
            })
        return pkgs

    @staticmethod
    def list_apk_packages(image, os_info):
        output = DockerLinuxInspector.run_docker(image, ["apk", "info", "-v"])
        pkgs = []
        for line in output.splitlines():
            if "-" not in line:
                continue
            name, version = line.rsplit("-", 1)
            pkgs.append({
                "name": name,
                "version": version,
                "type": "application",
                "ecosystem": os_info["id"]
            })
        return pkgs

    @staticmethod
    def list_pacman_packages(image, os_info):
        output = DockerLinuxInspector.run_docker(image, ["pacman", "-Q"])
        pkgs = []
        for line in output.splitlines():
            if " " not in line:
                continue
            name, version = line.split(" ", 1)
            pkgs.append({
                "name": name,
                "version": version,
                "type": "application",
                "ecosystem": os_info["id"]
            })
        return pkgs

    # ----------------------------------------------------------------------
    # HIGH-LEVEL DETECTION
    # ----------------------------------------------------------------------

    @staticmethod
    def detect_and_list_packages(image):
        os_info = DockerLinuxInspector.detect_os_info(image)
        pm = os_info["package_manager"]

        if pm == "dpkg":
            return DockerLinuxInspector.list_dpkg_packages(image, os_info), os_info
        if pm == "rpm":
            return DockerLinuxInspector.list_rpm_packages(image, os_info), os_info
        if pm == "apk":
            return DockerLinuxInspector.list_apk_packages(image, os_info), os_info
        if pm == "pacman":
            return DockerLinuxInspector.list_pacman_packages(image, os_info), os_info

        raise RuntimeError("Unsupported Linux package manager in image.")

    # ----------------------------------------------------------------------
    # PURL GENERATION (MIRRORS YOUR ORIGINAL CODE)
    # ----------------------------------------------------------------------

    @staticmethod
    def package_to_purl(os_info, pkg, version):
        os_id = os_info["id"].lower()

        # Debian / Ubuntu
        if os_info["package_manager"] == "dpkg":
            if "ubuntu" in os_id or "ubuntu" in os_info["like"].lower():
                return f"pkg:deb/ubuntu/{pkg}@{version}"
            return f"pkg:deb/debian/{pkg}@{version}"

        # RPM-Based
        if "almalinux" in os_id:
            return f"pkg:rpm/almalinux/{pkg}@{version}"
        if "redhat" in os_id:
            return f"pkg:rpm/redhat/{pkg}@{version}"
        if "centos" in os_id or "fedora" in os_id:
            return f"pkg:rpm/{os_id}/{pkg}@{version}"

        # Alpine
        if os_info["package_manager"] == "apk":
            return f"pkg:apk/alpine/{pkg}@{version}"

        raise RuntimeError("Unsupported Linux distribution for PURL generation.")

    # ----------------------------------------------------------------------
    # MAIN ENTRY POINT
    # ----------------------------------------------------------------------

    @staticmethod
    def inspect(image):
        packages, os_info = DockerLinuxInspector.detect_and_list_packages(image)

        purls = [
            DockerLinuxInspector.package_to_purl(os_info, p["name"], p["version"])
            for p in packages
        ]

        return {
            "os_info": os_info,
            "packages": packages,
            "purls": purls
        }

