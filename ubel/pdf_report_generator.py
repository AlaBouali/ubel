
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
from .info import __version__, __tool_name__
import html,json



class PDF_Report_Generator:

    @staticmethod
    def escape_html_tags(text):
        if not isinstance(text, str):
            text=json.dumps(text, indent=2)
        return html.escape(text).strip()

    @staticmethod
    def generate_report(system_type:str,check_mode:str,output_path:str,timestamp_date,allowed:bool,reason:str,policy:dict,stats:dict,severity_buckets:dict,vulnerabilities:list,inventory:list,findings_summary:dict):
        doc = SimpleDocTemplate(str(output_path), pagesize=A4)
        elements = []
        cell_style = ParagraphStyle(
            "cell",
            fontName="Helvetica",
            fontSize=8,
            leading=10
        )

        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        section_style = styles["Heading2"]
        normal_style = styles["Normal"]

        elements.append(Paragraph(f"Local Vulnerability Report by: {__tool_name__} v{__version__}", title_style))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"Date: {timestamp_date.strftime('%Y-%m-%d %H:%M:%S')}", title_style))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"Scan Type: {check_mode}", title_style))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"Scanned Ecosystem: {system_type} ( {check_mode} )", section_style))
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

        # -------------------------
        # Findings Summary
        # -------------------------

        elements.append(Paragraph("Findings Summary", section_style))
        elements.append(Spacer(1, 0.3 * inch))

        for pkg_name, pkg in findings_summary.items():

            elements.append(Paragraph(
                f"<b>{pkg['name']} {pkg['version']}</b>",
                section_style
            ))
            pkg_stats = [
                ListItem(Paragraph(f"{k.capitalize()}: {v}", normal_style))
                for k, v in pkg.get("stats", {}).items()
            ]

            elements.append(Paragraph(
                f"<b>Ecosystem:</b> {pkg['ecosystem']}<br/><b>Vulnerabilities stats:</b>",
                normal_style
            ))

            if pkg_stats:
                elements.append(ListFlowable(pkg_stats, bulletType="bullet"))
            else:
                elements.append(Paragraph("None", normal_style))

            elements.append(Spacer(1, 0.2 * inch))

            table_data = [[
                Paragraph("ID", cell_style),
                Paragraph("Severity", cell_style),
                Paragraph("Score", cell_style),
                Paragraph("Is Infection", cell_style),
                #Paragraph("Fixes", cell_style)
            ]]

            for v in pkg["vulnerabilities"]:

                fixes = v.get("fixes", [])

                if fixes:
                    fixes_text = "<br/>".join(
                        f"• {PDF_Report_Generator.escape_html_tags(f)}"
                        for f in fixes
                    )
                else:
                    fixes_text = "—"

                table_data.append([
                    Paragraph(v["id"], cell_style),
                    Paragraph(v["severity"], cell_style),
                    Paragraph(str(v["severity_score"]), cell_style),
                    Paragraph(str(v["is_infection"]), cell_style),
                    #Paragraph(fixes_text, cell_style)
                ])

            table = Table(
                table_data,
                colWidths=[110, 60, 40, 55, 170],
                repeatRows=1,
                splitByRow=1
            )

            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6e6e6")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))

            elements.append(table)
            elements.append(Spacer(1, 0.4 * inch))
            elements.append(PageBreak())

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
                                f"{indent_space}- {PDF_Report_Generator.escape_html_tags(str(item))}",
                                normal_style
                            )
                        )
                elements.append(Spacer(1, 0.1 * inch))

            else:
                value = PDF_Report_Generator.escape_html_tags(str(value))
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