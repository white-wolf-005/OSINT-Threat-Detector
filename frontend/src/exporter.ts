import { AnalysisReport, CorrelatedAnalytics, PortRiskProfile, SourceResultItem } from "./types.js";

export class IntelligenceExporter {
    private static triggerFileDownload(filename: string, content: string, mimeType: string): void {
        const blob: Blob = new Blob([content], { type: mimeType });
        const objectUrl: string = URL.createObjectURL(blob);
        const anchor: HTMLAnchorElement = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        document.body.removeChild(anchor);
        URL.revokeObjectURL(objectUrl);
    }

    private static sanitizeFilename(target: string): string {
        return target.replace(/[^a-zA-Z0-9._-]/g, "_");
    }

    public static exportJson(report: AnalysisReport, analytics: CorrelatedAnalytics): void {
        const payload: Record<string, unknown> = {
            generated_at: new Date().toISOString(),
            engine: "OSINT Threat Intelligence Engine v2.0",
            report: report,
            analytics: analytics,
        };
        const safeName: string = IntelligenceExporter.sanitizeFilename(report.target);
        IntelligenceExporter.triggerFileDownload(
            "osint_report_" + safeName + ".json",
            JSON.stringify(payload, null, 2),
            "application/json;charset=utf-8"
        );
    }

    public static exportCsv(report: AnalysisReport, analytics: CorrelatedAnalytics): void {
        const rows: string[][] = [
            ["Target", "Resolved_IP", "Type", "Threat_Score", "Risk_Level", "Open_Ports", "CVEs_Detected", "Source_Count"],
            [
                report.target,
                report.resolved_ip || "N/A",
                report.type,
                String(report.threat_score),
                analytics.riskLevel,
                analytics.portProfiles.map((p: PortRiskProfile): string => String(p.port) + "/" + p.service).join("; ") || "None",
                analytics.cveDescriptors.map((c): string => c.cveId).join("; ") || "None",
                String(report.sources_checked),
            ],
        ];

        const csvString: string = rows
            .map((row: string[]): string =>
                row.map((cell: string): string => '"' + cell.replace(/"/g, '""') + '"').join(",")
            )
            .join("\r\n");

        const safeName: string = IntelligenceExporter.sanitizeFilename(report.target);
        IntelligenceExporter.triggerFileDownload(
            "osint_report_" + safeName + ".csv",
            csvString,
            "text/csv;charset=utf-8"
        );
    }

    public static exportMarkdown(report: AnalysisReport, analytics: CorrelatedAnalytics): void {
        const lines: string[] = [
            "OSINT Threat Intelligence Report: " + report.target,
            "====================================================",
            "",
            "* Generated At: " + new Date().toUTCString(),
            "* Indicator Type: " + report.type,
            "* Resolved IPv4: " + (report.resolved_ip || "N/A"),
            "* Heuristic Threat Score: " + String(report.threat_score) + " / 100",
            "* Risk Classification: " + analytics.riskLevel,
            "",
            "Executive Summary",
            "=================",
            analytics.executiveSummary,
            "",
            "Pillar Breakdown",
            "================",
        ];

        analytics.pillars.forEach((pillar): void => {
            lines.push(
                "* " +
                    pillar.title +
                    " (" +
                    pillar.statusLabel +
                    " - Impact: " +
                    String(pillar.scoreImpact) +
                    "/" +
                    String(pillar.maxImpact) +
                    ")"
            );
            pillar.findings.forEach((finding: string): void => {
                lines.push("  * " + finding);
            });
            lines.push("");
        });

        if (analytics.portProfiles.length > 0) {
            lines.push("Exposed Network Ports");
            lines.push("=====================");
            analytics.portProfiles.forEach((p: PortRiskProfile): void => {
                lines.push(
                    "* Port " +
                        String(p.port) +
                        " (" +
                        p.service +
                        " / " +
                        p.protocol +
                        ") - Severity: " +
                        p.severity +
                        " - " +
                        p.rationale
                );
            });
            lines.push("");
        }

        lines.push("Raw Intelligence Feeds");
        lines.push("======================");
        report.results.forEach((res: SourceResultItem): void => {
            const statusText: string = res.error ? "Error (" + res.error + ")" : "Telemetry Collected";
            lines.push("* " + res.source + ": " + statusText);
        });

        const safeName: string = IntelligenceExporter.sanitizeFilename(report.target);
        IntelligenceExporter.triggerFileDownload(
            "osint_report_" + safeName + ".md",
            lines.join("\n"),
            "text/markdown;charset=utf-8"
        );
    }
}