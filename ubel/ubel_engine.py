import requests,datetime,json,os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    ListFlowable,
    ListItem,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
import json,sys,re,html,os
from .policy import evaluate_policy
from .python_runner import Pypi_Manager
from .linux_runner import Linux_Manager
from .docker_runner import DockerLinuxInspector
from .node_runner import Node_Manager
from .cvss_parser import CVSS_Parser
from .info import __version__ , __tool_name__



class Ubel_Engine:

    osv_endpoint="https://api.osv.dev/v1/querybatch"

    reports_location="./.ubel/local/reports"

    generated_dependencies_location="./.ubel/dependencies/"

    default_policy={
        "infections":"block",
        "severity":{
            "critical":"block",
            "high":"block",
            "medium":"allow",
            "low":"allow",
            "unknown":"allow"
        }
    }

    check_mode="health"

    system_type="pypi"

    engine="pip"

    policy_dir="./.ubel/local/policy/"
    policy_filename="config.json"

    @staticmethod
    def escape_html_tags(text):
        if not isinstance(text, str):
            text=json.dumps(text, indent=2)
        return html.escape(text).strip()

    @staticmethod
    def generate_requirements_file(purls):
        requirements_filename="requirements.txt"
        os.makedirs(Ubel_Engine.generated_dependencies_location,exist_ok=True)
        requirements_file=f"{Ubel_Engine.generated_dependencies_location}/{requirements_filename}"
        components=[Ubel_Engine.get_dependency_from_purl(purl) for purl in purls]
        lines=[f"{comp[0]}=={comp[1]}" for comp in components]
        data="\n".join(lines)
        with open(requirements_file,"w") as file:
            file.write(data)
            file.close()
        return requirements_file

    @staticmethod
    def load_policy():
        Ubel_Engine.initiate_local_policy()
        policy_file=f"{Ubel_Engine.policy_dir}/{Ubel_Engine.policy_filename}"
        with open(policy_file,"r") as file:
            data=json.load(file)
            file.close()
            return data

    @staticmethod
    def initiate_local_policy():
        os.makedirs(Ubel_Engine.policy_dir,exist_ok=True)
        policy_file=f"{Ubel_Engine.policy_dir}/{Ubel_Engine.policy_filename}"
        needs_creation=False
        if os.path.exists(policy_file)==False:
            needs_creation=True
        if needs_creation==False:
            if os.path.getsize(policy_file)==0:
                os.remove(policy_file)
                needs_creation=True
        if needs_creation==True:
            with open(policy_file,"w") as file:
                json.dump(Ubel_Engine.default_policy,file,indent=4)
                file.close()

    @staticmethod
    def parse_pip_report(data):
        components_list=data.get("install",[])
        purls=[]
        for item in components_list:
            name=item["metadata"]["name"].lower()
            version=item["metadata"]["version"]
            purl=f"pkg:pypi/{name}@{version}"
            purls.append(purl)
        return purls
    
    @staticmethod
    def get_dependency_from_purl(purl:str):
        if purl.startswith("pkg:pypi/") or purl.startswith("pkg:npm/"):
            info=purl.split(f"{Ubel_Engine.system_type}/")[1]
        else:
                info=purl.split("/")[-1]
        if info.count("@")!=1:
            info_version=info.split("@")[-1] 
            info_name=info.split(f"@{info_version}")[0]
            return info_name,info_version
        return info.split("@")
    
    @staticmethod
    def get_inventory_from_purls(purls):
        os_info=Linux_Manager.get_os_info()
        inventory=[]
        for purl in purls:
            dep_info=Ubel_Engine.get_dependency_from_purl(purl)
            item={
                "id":purl,
                "name":dep_info[0],
                "version":dep_info[1],
                "ecosystem":Ubel_Engine.system_type if Ubel_Engine.system_type!="linux" else os_info["id"],
                "type":"library" if Ubel_Engine.system_type!="linux" else "application",
                "state":"undetermined"
            }
            inventory.append(item)
        return inventory
    
    @staticmethod
    def submit_to_osv(purls_list):
        if purls_list==[]:
            return []
        page=0
        page_pace=800
        initial_vulnerabilities_list = []
        while True:
            purls=purls_list[page:page_pace+page]
            page+=page_pace
            if purls==[]:
                break
            queries=[]
            for item in purls:
                queries.append({ "package": { "purl": item } })
            response=requests.post("https://api.osv.dev/v1/querybatch",json={"queries":queries},headers={"User-Agent": "ubel_tool"},timeout=60)
            if response.status_code==200:
                vulns=response.json().get("results",[])
                pace=0
                for item in vulns:
                    purl=purls[pace]
                    pace+=1
                    purl_info=Ubel_Engine.get_dependency_from_purl(purl)
                    dep=purl_info[0]
                    dep_version=purl_info[1]
                    for vul in item.get('vulns',[]):
                        initial_vulnerabilities_list.append({"purl":purl,"vulnerability_id":vul['id'],"dependency":dep,"affected_version":dep_version})
            else:
                print(response.json())
                response.raise_for_status()
        return initial_vulnerabilities_list

    @staticmethod
    def generate_fix(ranges,versions,package,ecosystem):
        fixed_versions=[]
        still_vulnerable_versions=[]
        for item in ranges:
            for event in item["events"]:
                if "fixed" in event:
                    fixed_versions.append(event["fixed"])
                elif "last_affected" in event:
                    still_vulnerable_versions.append(event["last_affected"])
        if still_vulnerable_versions==[]:
            still_vulnerable_versions=versions
        if fixed_versions!=[]:
            return f"Upgrade {package} ( {ecosystem} ) to: {' or '.join(fixed_versions)}"
        elif still_vulnerable_versions!=[]:
            return f"Upgrade {package} ( {ecosystem} ) to a version higher than: {' or '.join(still_vulnerable_versions)}"
        return f"No fix available for {package}"

    @staticmethod
    def get_fix(vuln:dict):
        remediations=[]
        affected_info=vuln["affected"]
        dependency=vuln["affected_dependency"]
        for item in affected_info:
            package=item.get("package",{})
            ranges=item.get("ranges",[])
            versions=item.get("versions",[])
            if package.get("name").lower()==dependency.lower():
                ecosystem=package.get("ecosystem")
                remediations.append(Ubel_Engine.generate_fix(ranges,versions,package["name"],ecosystem))
        vuln["fixes"]=remediations
        vuln["has_fix"]=len(remediations)>0
        vuln["description"]=vuln.get("description",vuln.get("details",vuln.get("summary","")))
        if "details" in vuln:
            del vuln["details"]
        if "summary" in vuln:
            del vuln["summary"]

    
    @staticmethod
    def get_vul_by_id(vuln:dict):
        vuln_id=vuln["vulnerability_id"]
        purl=vuln["purl"]
        removable_info=["database_specific","affected","schema_version"]
        url=f"https://api.osv.dev/v1/vulns/{vuln_id}"
        response=requests.get(url,headers={"User-Agent": "ubel_tool"},timeout=60)
        if response.status_code!=200:
            return
        data=response.json()
        CVSS_Parser.process_vulnerability(data)
        data["affected_purl"]=purl
        data["affected_dependency"]=vuln["dependency"]
        data["affected_dependency_version"]=vuln["affected_version"]
        data["url"]=f"https://osv.dev/vulnerability/{vuln_id}"
        data["is_infection"]=data["id"].startswith("MAL-")
        Ubel_Engine.get_fix(data)
        for item in removable_info:
            if item in data:
                del data[item]
        return data
     
    @staticmethod
    def dict_to_str(data, indent=0, step=4):
        """
        Recursively pretty-print a dict (and lists) with clean indentation.
        """
        lines = []
        pad = " " * indent

        if isinstance(data, dict):
            for key, value in data.items():
                lines.append(f"{pad}{key}:")
                if isinstance(value, (dict, list)):
                    lines.append(Ubel_Engine.dict_to_str(value, indent + step, step))
                else:
                    lines.append(" " * (indent + step) + str(value))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    lines.append(Ubel_Engine.dict_to_str(item, indent + step, step))
                else:
                    lines.append(" " * indent + f"- {item}")
        else:
            lines.append(pad + str(data))

        return "\n".join(lines)
    
    @staticmethod
    def set_inventory_state(infected_purls, vulnerable_purls, inventory):
        for item in inventory:
            state="safe"
            if item.get("id") in infected_purls:
                state="infected"
            elif item.get("id") in vulnerable_purls:
                state="vulnerable"
            item["state"] = state

    
    @staticmethod
    def scan(pip_args):
        # ----------------------------------
        # Prepare Output Paths
        # ----------------------------------
        timestamp_date= datetime.datetime.now(datetime.UTC)
        timestamp=timestamp_date.strftime("%Y_%m_%d__%H_%M_%S")
        date_path="/".join(timestamp.split("_")[:3])
        output_dir = Path(f'{Ubel_Engine.reports_location}/{Ubel_Engine.system_type}/{Ubel_Engine.check_mode}/{date_path}')
        output_dir.mkdir(parents=True, exist_ok=True)

        base_file_name = f"{Ubel_Engine.system_type}_{Ubel_Engine.check_mode}_{Ubel_Engine.engine}__{timestamp}"
        pdf_path = output_dir / f"{base_file_name}.pdf"
        json_path = output_dir / f"{base_file_name}.json"
        artifact_path = output_dir / f"{base_file_name}__artifact.{Ubel_Engine.system_type}"
        policy=Ubel_Engine.load_policy()
        purls=[]
        report_content=None
        if Ubel_Engine.system_type=="pypi":
            if Ubel_Engine.check_mode in ["check","install"]:
                report_content = Pypi_Manager.run_dry_run(pip_args)
                if isinstance(report_content, str):
                    report_content = json.loads(report_content)

                purls = Ubel_Engine.parse_pip_report(report_content)
            else:
                purls=Pypi_Manager.get_installed()
                packages=[Ubel_Engine.get_dependency_from_purl(purl) for purl in purls]
                report_content=Pypi_Manager.get_installed_inventory()
        elif Ubel_Engine.system_type=="npm":
            if Ubel_Engine.check_mode in ["check","install"]:
                purls = Node_Manager.run_dry_run(pip_args)
                report_content = Node_Manager.current_lock_file_content
                packages=[Ubel_Engine.get_dependency_from_purl(purl) for purl in purls]
            else:
                purls=Node_Manager.get_installed(Ubel_Engine.engine)
                packages=[Ubel_Engine.get_dependency_from_purl(purl) for purl in purls]
                if Ubel_Engine.engine=="npm":
                    with open("package-lock.json","r",encoding="utf-8") as af:
                        report_content=json.load(af)
                        af.close()
        elif Ubel_Engine.system_type=="docker":
            report_content = DockerLinuxInspector.inspect(pip_args[0])
            purls = report_content.get("purls",[])
            packages = report_content.get("packages",[]) 
        else:
            if Ubel_Engine.check_mode in ["check","install"]:
                packages=Linux_Manager.resolve_packages(pip_args)
                system_info=Linux_Manager.get_os_info()
                report_content={"packages":packages,"system_info":system_info}
                purls=[Linux_Manager.package_to_purl(system_info["id"],pkg["name"],pkg["version"]) for pkg in packages]
            else:
                purls=Linux_Manager.get_linux_packages()
                packages=Ubel_Engine.get_inventory_from_purls(purls)
                system_info=Linux_Manager.get_os_info()
                report_content={"packages":packages,"system_info":system_info}
        vuln_ids = Ubel_Engine.submit_to_osv(purls)

        purls=list(set(purls))
        inventory=Ubel_Engine.get_inventory_from_purls(purls)

        vulnerabilities = []
        max_workers = min(40, len(vuln_ids))
        if vuln_ids!=[]:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_vid = {
                    executor.submit(Ubel_Engine.get_vul_by_id, vid): vid
                    for vid in vuln_ids
                }

                for future in as_completed(future_to_vid):
                    try:
                        v = future.result()
                        if v:
                            vulnerabilities.append(v)
                    except Exception as e:
                        # Fail-soft: do not crash entire scan because one vuln fetch failed
                        print(f"[!] Failed to fetch vulnerability: {e}")

        # ----------------------------------
        # Compute Stats
        # ----------------------------------
        severity_buckets = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
        }

        infection_count = 0

        vulnerable_purls = set()
        infected_purls = set()

        for v in vulnerabilities:
            sev = (v.get("severity") or "unknown").lower()
            if sev not in severity_buckets:
                sev = "unknown"
            severity_buckets[sev] += 1

            if v.get("is_infection"):
                infection_count += 1
                infected_purls.add(v.get("affected_purl"))
            else:
                vulnerable_purls.add(v.get("affected_purl"))
        

        Ubel_Engine.set_inventory_state(infected_purls, vulnerable_purls, inventory)

        stats = {
            "inventory_size": len(inventory),
            "inventory_stats": {
                "infected": len(infected_purls),
                "vulnerable": len(vulnerable_purls),
                "safe": len(inventory) - len(infected_purls) - len(vulnerable_purls),
            },
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities_stats":{"severity": severity_buckets},
            "total_infections": infection_count,
        }


        # ----------------------------------
        # Save JSON
        # ----------------------------------
        final_json = {
            "generated_at": timestamp_date.isoformat() + "Z",
            "tool_info": {
                "name": __tool_name__,
                "version": __version__
            },
            "stats": stats,
            "vulnerabilities": vulnerabilities,
            "inventory": inventory,
            "policy":policy,
        }

        allowed, reason = evaluate_policy(final_json)


        final_json.update({"decision": {
                "allowed": allowed,
                "reason": reason,
            }})

        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(final_json, jf, indent=2)
        
        with open(artifact_path, "w", encoding="utf-8") as af:
            af.write(json.dumps(report_content, indent=2))
            af.close()

        # ----------------------------------
        # Generate PDF
        # ----------------------------------
        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
        elements = []

        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        section_style = styles["Heading2"]
        normal_style = styles["Normal"]

        elements.append(Paragraph(f"Local Vulnerability Report by: {__tool_name__} v{__version__}", title_style))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"Date: {timestamp_date.strftime('%Y-%m-%d %H:%M:%S')}", title_style))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"Scan Type: {Ubel_Engine.check_mode}", title_style))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"Scanned Ecosystem: {Ubel_Engine.system_type} ( {Ubel_Engine.engine} )", section_style))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"Scan Decision: {'ALLOWED' if allowed else 'BLOCKED'} - {reason}", section_style))
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph("Policy Details", section_style))
        elements.append(Spacer(1, 0.3 * inch))

        for k, v in policy.items():
            if isinstance(v, dict):
                elements.append(Paragraph(f"<b>{k.capitalize()}:</b>", normal_style))
                sub_list = [
                    ListItem(Paragraph(f"{sk.capitalize()}: {sv}", normal_style))
                    for sk, sv in v.items()
                ]
                elements.append(ListFlowable(sub_list, bulletType="bullet"))
            else:
                elements.append(Paragraph(f"<b>{k.capitalize()}:</b> {v}", normal_style))
            elements.append(Spacer(1, 0.2 * inch))
        # ---------- Stats Section ----------
        elements.append(Paragraph("Statistics Summary", section_style))
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph(
            f"<b>Inventory Size:</b> {stats['inventory_size']}",
            normal_style
        ))
        elements.append(Spacer(1, 0.2 * inch))
        inventory_list = [
            ListItem(Paragraph(f"{k.capitalize()}: {v}", normal_style))
            for k, v in stats['inventory_stats'].items()
        ]
        elements.append(ListFlowable(inventory_list, bulletType="bullet"))
        elements.append(Spacer(1, 0.5 * inch))
        elements.append(Paragraph(
            f"<b>Infections:</b> {stats['total_infections']}",
            normal_style
        ))
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(
            f"<b>Total Vulnerabilities:</b> {stats['total_vulnerabilities']}",
            normal_style
        ))

        severity_list = [
            ListItem(Paragraph(f"{k.capitalize()}: {v}", normal_style))
            for k, v in severity_buckets.items()
        ]
        elements.append(ListFlowable(severity_list, bulletType="bullet"))
        elements.append(Spacer(1, 0.5 * inch))

        #elements.append(PageBreak())
        

        # ---------- FULL JSON RENDER ----------
        elements.append(Paragraph("Vulnerability Details", section_style))
        elements.append(Spacer(1, 0.3 * inch))


        def render_value(key, value, indent_level=0):
            indent_space = "&nbsp;" * (indent_level * 4)

            if isinstance(value, dict):
                elements.append(
                    Paragraph(f"{indent_space}<b>{key}:</b>", normal_style)
                )
                elements.append(Spacer(1, 0.1 * inch))
                for k, v in value.items():
                    render_value(k, v, indent_level + 1)

            elif isinstance(value, list):
                elements.append(
                    Paragraph(f"{indent_space}<b>{key}:</b>", normal_style)
                )
                elements.append(Spacer(1, 0.1 * inch))

                for item in value:
                    if isinstance(item, dict):
                        elements.append(
                            Paragraph(f"{indent_space}-", normal_style)
                        )
                        for k, v in item.items():
                            render_value(k, v, indent_level + 2)
                    else:
                        elements.append(
                            Paragraph(
                                f"{indent_space}- {Ubel_Engine.escape_html_tags(str(item))}",
                                normal_style
                            )
                        )
                elements.append(Spacer(1, 0.1 * inch))

            else:
                value = Ubel_Engine.escape_html_tags(str(value))
                safe_value = str(value).replace("\n", "<br/>")
                elements.append(
                    Paragraph(
                        f"{indent_space}<b>{key}:</b> {safe_value}",
                        normal_style
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))


        for v in vulnerabilities:
            elements.append(Spacer(1, 0.4 * inch))
            elements.append(
                Paragraph(
                    f"<b>{v.get('affected_dependency')} "
                    f"{v.get('affected_dependency_version')}</b>",
                    section_style
                )
            )
            elements.append(Spacer(1, 0.2 * inch))

            for key, value in v.items():
                render_value(key, value)

            elements.append(Spacer(1, 0.5 * inch))
        
        # ----------------------------------
        # Inventory Table Section
        # ----------------------------------

        elements.append(PageBreak())
        elements.append(Paragraph("Inventory Table", section_style))
        elements.append(Spacer(1, 0.3 * inch))

        # Paragraph style for wrapped and centered text
        cell_style = ParagraphStyle(
            "cell_style",
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            alignment=TA_CENTER,    # horizontal center
        )

        # Header row
        inventory_data = [
            [
                Paragraph("ID", cell_style),
                Paragraph("Name", cell_style),
                Paragraph("Version", cell_style),
                Paragraph("Ecosystem", cell_style),
                Paragraph("Type", cell_style),
                Paragraph("State", cell_style),
            ]
        ]

        # Convert each field into a wrapped centered Paragraph
        for v in inventory:
            inventory_data.append([
                Paragraph(str(v.get("id", "")), cell_style),
                Paragraph(str(v.get("name", "")), cell_style),
                Paragraph(str(v.get("version", "")), cell_style),
                Paragraph(str(v.get("ecosystem", "")), cell_style),
                Paragraph(str(v.get("type", "")), cell_style),
                Paragraph(str(v.get("state", "")), cell_style),
            ])

        # Set column widths — prevents overflow + enforces clean layout
        col_widths = [50, 120, 60, 80, 70, 60]

        table = Table(inventory_data, colWidths=col_widths, repeatRows=1)

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6e6e6")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),

            # Center vertically
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),

            # Center alignment (Paragraph handles internal text centering)
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),

            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 0.5 * inch))

        doc.build(elements)
        print()
        print("Policy:")
        print()
        print(Ubel_Engine.dict_to_str(policy))
        print()
        print()
        print("Findings:")
        print()
        print(Ubel_Engine.dict_to_str(final_json["stats"]))
        print()
        print()
        print(f"Policy Decision: {'ALLOW' if allowed else 'BLOCK'}")
        print()
        print()
        print(f"PDF report saved to: {pdf_path}")
        print(f"JSON report saved to: {json_path}")
        print(f"Scan artifact saved to: {artifact_path}")
        print()
        print()
        if not allowed:
            print(f"[!] {reason}")
            sys.exit(1)
        if Ubel_Engine.check_mode in ["health","check"]:
            sys.exit(0)
        print("[+] Policy passed. Installing dependencies...")
        if Ubel_Engine.system_type=="pypi":
            file_path=Ubel_Engine.generate_requirements_file(purls)
            Pypi_Manager.run_real_install(file_path,Ubel_Engine.engine)
        elif Ubel_Engine.system_type=="npm":
            packages=[Ubel_Engine.get_dependency_from_purl(purl) for purl in purls]
            Node_Manager.run_real_install(packages,Ubel_Engine.engine)
        else:
            packages=[Ubel_Engine.get_dependency_from_purl(purl) for purl in purls]
            Linux_Manager.run_real_install(packages)