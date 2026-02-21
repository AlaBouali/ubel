import argparse
import sys
import json

from .ubel_engine import Ubel_Engine
from .python_runner import Pypi_Manager
from .linux_runner import Linux_Manager
from pathlib import Path
from .utils import load_environment, create_output_dir, download_file
from .policy import evaluate_policy
from .info import banner


def print_banner():

    print(banner)
    print()
    print(f"Reports location: {Ubel_Engine.reports_location}")
    print()

    print(f"Policy location: {Ubel_Engine.policy_dir}")
    print()

def set_policy_rules(action,severities):
    data=Ubel_Engine.load_policy()
    for rule in data["severity"]:
        if rule in severities:
            data["severity"][rule]=action
    with open(f"{Ubel_Engine.policy_dir}/{Ubel_Engine.policy_filename}","w") as file:
        json.dump(data,file,indent=4)
        file.close()

def non_linux_mode(pkg_manager,ecosystem,description):

    print_banner()
    
    parser = argparse.ArgumentParser(
        description=description
    )

    parser.add_argument(
        "mode",
        choices=["check", "install", "health", "init","allow","block"],
        help="Execution mode"
    )

    parser.add_argument(
        "extra_args",
        nargs="*",
        help="Arguments passed after mode"
    )

    Ubel_Engine.engine=pkg_manager
    Ubel_Engine.system_type=ecosystem

    args = parser.parse_args()
    Ubel_Engine.initiate_local_policy()
    if args.mode:
        Ubel_Engine.check_mode=args.mode
    else:
        Ubel_Engine.check_mode="init"
    
    if Ubel_Engine.check_mode=="init":
        sys.exit(0)
    

    api_key, asset_id, endpoint = load_environment()
    pkgs=[]
    if args.extra_args in [None,[]] and pkg_manager=="pip" and Ubel_Engine.check_mode in ["check","install"]:
        with open("requirements.txt","r") as requirement_file:
            lines=requirement_file.readlines()
            requirement_file.close()
        pkgs=[line.strip() for line in lines if line.strip()!=""]
    else:
        pkgs=args.extra_args
    

    if Ubel_Engine.check_mode in ["allow","block"]:
        set_policy_rules(args.mode,args.extra_args)
        sys.exit(0)

    if not api_key and not asset_id:
        Ubel_Engine.scan(pkgs)
        sys.exit(0)


def linux_mode():
    parser = argparse.ArgumentParser(
        description="Safe Linux policy-driven supply-chain firewall"
    )
    Ubel_Engine.initiate_local_policy()

    Ubel_Engine.system_type=Linux_Manager.get_os_info()["id"]
    Ubel_Engine.reports_location=f'{Path.home()}/{Ubel_Engine.reports_location}'
    Ubel_Engine.policy_dir=f'{Path.home()}/{Ubel_Engine.policy_dir}'

    print(banner)
    print()
    print(f"Reports location: {Ubel_Engine.reports_location}")
    print()

    print(f"Policy location: {Ubel_Engine.policy_dir}")
    print()

    parser.add_argument(
        "mode",
        choices=["check", "install", "health", "init","allow","block"],
        help="Execution mode"
    )

    parser.add_argument(
        "extra_args",
        nargs="*",
        help="Arguments passed after mode"
    )

    args = parser.parse_args()
    Ubel_Engine.initiate_local_policy()
    if args.mode:
        Ubel_Engine.check_mode=args.mode
    else:
        Ubel_Engine.check_mode="init"
    if Ubel_Engine.check_mode=="init":
        sys.exit(0)
    
    if Ubel_Engine.check_mode in ["allow","block"]:
        set_policy_rules(args.mode,args.extra_args)
        sys.exit(0)

    api_key, asset_id, endpoint = load_environment()
    if not api_key and not asset_id:
        Ubel_Engine.scan(args.extra_args)
        sys.exit(0)


def pip_mode():
    non_linux_mode("pip","pypi","Safe Python policy-driven supply-chain firewall")


def npm_mode():
    non_linux_mode("npm","npm","Safe Node.js policy-driven supply-chain firewall")