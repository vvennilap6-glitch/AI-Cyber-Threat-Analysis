from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors


def generate_incident_report(
    incident_data,
    output_path
):

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    elements = []

    # =====================================================
    # TITLE
    # =====================================================

    elements.append(
        Paragraph(
            "SECURITY INCIDENT REPORT",
            styles["Title"]
        )
    )

    elements.append(
        Spacer(
            1,
            0.3 * inch
        )
    )


    # =====================================================
    # INCIDENT OVERVIEW
    # =====================================================

    elements.append(
        Paragraph(
            "Incident Overview",
            styles["Heading2"]
        )
    )


    overview_data = [

        [
            "Incident Severity",
            str(
                incident_data.get(
                    "incident_severity",
                    "Unknown"
                )
            )
        ],

        [
            "Threat Priority Score",
            str(
                incident_data.get(
                    "threat_priority_score",
                    0
                )
            )
        ],

        [
            "Artifact Type",
            str(
                incident_data.get(
                    "affected_artifact",
                    {}
                ).get(
                    "type",
                    "Unknown"
                )
            )
        ],

        [
            "Target",
            str(
                incident_data.get(
                    "affected_artifact",
                    {}
                ).get(
                    "target",
                    "Unknown"
                )
            )
        ],

        [
            "Classification",
            str(
                incident_data.get(
                    "classification",
                    "Unknown"
                )
            )
        ],

        [
            "Risk Score",
            f"{incident_data.get('risk_score', 0)}/100"
        ]

    ]


    overview_table = Table(
        overview_data,
        colWidths=[
            2 * inch,
            4 * inch
        ]
    )


    overview_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),

            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            )

        ])
    )


    elements.append(
        overview_table
    )

    elements.append(
        Spacer(
            1,
            0.3 * inch
        )
    )


    # =====================================================
    # INCIDENT SUMMARY
    # =====================================================

    elements.append(
        Paragraph(
            "Incident Summary",
            styles["Heading2"]
        )
    )


    elements.append(
        Paragraph(
            str(
                incident_data.get(
                    "incident_summary",
                    "No incident summary available."
                )
            ),
            styles["BodyText"]
        )
    )

    elements.append(
        Spacer(
            1,
            0.2 * inch
        )
    )


    # =====================================================
    # HELPER FUNCTION
    # =====================================================

    def add_section(
        title,
        items
    ):

        elements.append(
            Paragraph(
                title,
                styles["Heading2"]
            )
        )


        if not items:

            elements.append(
                Paragraph(
                    "No information available.",
                    styles["BodyText"]
                )
            )

        else:

            for index, item in enumerate(
                items,
                start=1
            ):

                elements.append(
                    Paragraph(
                        f"{index}. {item}",
                        styles["BodyText"]
                    )
                )


        elements.append(
            Spacer(
                1,
                0.2 * inch
            )
        )


    # =====================================================
    # SECURITY FINDINGS
    # =====================================================

    add_section(
        "Security Findings",
        incident_data.get(
            "security_findings",
            []
        )
    )


    # =====================================================
    # IMMEDIATE ACTIONS
    # =====================================================

    add_section(
        "Recommended Immediate Actions",
        incident_data.get(
            "immediate_actions",
            []
        )
    )


    # =====================================================
    # CONTAINMENT STEPS
    # =====================================================

    add_section(
        "Containment Steps",
        incident_data.get(
            "containment_steps",
            []
        )
    )


    # =====================================================
    # INVESTIGATION STEPS
    # =====================================================

    add_section(
        "Investigation Steps",
        incident_data.get(
            "investigation_steps",
            []
        )
    )


    # =====================================================
    # RELATED INVESTIGATIONS
    # =====================================================

    elements.append(
        Paragraph(
            "Related Investigations",
            styles["Heading2"]
        )
    )


    related_count = incident_data.get(
        "related_investigations",
        0
    )


    elements.append(
        Paragraph(
            f"Related investigations detected: {related_count}",
            styles["BodyText"]
        )
    )


    elements.append(
        Spacer(
            1,
            0.3 * inch
        )
    )


    # =====================================================
    # FOOTER
    # =====================================================

    elements.append(
        Paragraph(
            "Generated by AI Cyber Threat Analysis Platform",
            styles["Italic"]
        )
    )


    # =====================================================
    # BUILD PDF
    # =====================================================

    document.build(
        elements
    )


    return output_path