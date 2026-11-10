import { ThreatAnalyticsEngine } from "./analytics.js";
import { DashboardComponents } from "./components.js";
import { IntelligenceExporter } from "./exporter.js";
import {
    AnalysisReport,
    AnalyzeApiResponse,
    CorrelatedAnalytics,
    HealthApiResponse,
    HistoryApiResponse,
    HistoryFilterCategory,
    HistoryRecordItem,
    StatsApiResponse,
    ValidationOutcome,
} from "./types.js";
import { IOCValidator } from "./validator.js";

export class OSINTDashboardApp {
    private currentReport: AnalysisReport | null = null;
    private currentAnalytics: CorrelatedAnalytics | null = null;
    private cachedHistory: HistoryRecordItem[] = [];

    private readonly formEl: HTMLFormElement;
    private readonly targetInputEl: HTMLInputElement;
    private readonly submitBtnEl: HTMLButtonElement;
    private readonly iocBadgeEl: HTMLElement;
    private readonly validationHintEl: HTMLElement;
    private readonly loadingEl: HTMLElement;
    private readonly errorAlertEl: HTMLElement;
    private readonly resultAreaEl: HTMLElement;
    private readonly historyAreaEl: HTMLElement;
    private readonly historyFilterEl: HTMLSelectElement;
    private readonly historySearchEl: HTMLInputElement;

    constructor() {
        this.formEl = document.getElementById("analyzeForm") as HTMLFormElement;
        this.targetInputEl = document.getElementById("target") as HTMLInputElement;
        this.submitBtnEl = document.getElementById("submitBtn") as HTMLButtonElement;
        this.iocBadgeEl = document.getElementById("iocPreviewBadge") as HTMLElement;
        this.validationHintEl = document.getElementById("validationHint") as HTMLElement;
        this.loadingEl = document.getElementById("loading") as HTMLElement;
        this.errorAlertEl = document.getElementById("errorAlert") as HTMLElement;
        this.resultAreaEl = document.getElementById("resultArea") as HTMLElement;
        this.historyAreaEl = document.getElementById("historyArea") as HTMLElement;
        this.historyFilterEl = document.getElementById("historyFilterType") as HTMLSelectElement;
        this.historySearchEl = document.getElementById("historySearchInput") as HTMLInputElement;
    }

    public async init(): Promise<void> {
        this.bindEvents();
        await Promise.all([this.checkHealth(), this.refreshStats(), this.loadHistory()]);
    }

    private bindEvents(): void {
        this.targetInputEl.addEventListener("input", (): void => {
            this.handleLiveValidation();
        });

        this.formEl.addEventListener("submit", async (event: SubmitEvent): Promise<void> => {
            event.preventDefault();
            await this.executeAnalysis();
        });

        const presetButtons: NodeListOf<HTMLButtonElement> = document.querySelectorAll(".preset-btn");
        presetButtons.forEach((btn: HTMLButtonElement): void => {
            btn.addEventListener("click", async (): Promise<void> => {
                const presetTarget: string = btn.getAttribute("data-preset") || "";
                if (presetTarget) {
                    this.targetInputEl.value = presetTarget;
                    this.handleLiveValidation();
                    await this.executeAnalysis();
                }
            });
        });

        const loadHistoryBtn: HTMLElement | null = document.getElementById("loadHistoryBtn");
        if (loadHistoryBtn) {
            loadHistoryBtn.addEventListener("click", async (): Promise<void> => {
                await this.loadHistory();
            });
        }

        this.historyFilterEl.addEventListener("change", (): void => {
            this.renderFilteredHistory();
        });

        this.historySearchEl.addEventListener("input", (): void => {
            this.renderFilteredHistory();
        });

        document.getElementById("exportJsonBtn")?.addEventListener("click", (): void => {
            if (this.currentReport && this.currentAnalytics) {
                IntelligenceExporter.exportJson(this.currentReport, this.currentAnalytics);
            }
        });

        document.getElementById("exportCsvBtn")?.addEventListener("click", (): void => {
            if (this.currentReport && this.currentAnalytics) {
                IntelligenceExporter.exportCsv(this.currentReport, this.currentAnalytics);
            }
        });

        document.getElementById("exportMdBtn")?.addEventListener("click", (): void => {
            if (this.currentReport && this.currentAnalytics) {
                IntelligenceExporter.exportMarkdown(this.currentReport, this.currentAnalytics);
            }
        });
    }

    private handleLiveValidation(): ValidationOutcome {
        const outcome: ValidationOutcome = IOCValidator.inspect(this.targetInputEl.value);
        this.validationHintEl.textContent = outcome.advisoryMessage;

        if (!this.targetInputEl.value.trim()) {
            this.iocBadgeEl.textContent = "Awaiting IOC Input";
            this.iocBadgeEl.className =
                "text-xs font-mono px-2.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700";
            return outcome;
        }

        if (outcome.isValid) {
            this.iocBadgeEl.textContent = "VALID " + outcome.detectedCategory.toUpperCase();
            this.iocBadgeEl.className =
                "text-xs font-mono px-2.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800";
        } else {
            this.iocBadgeEl.textContent = outcome.isPrivateNetwork ? "PRIVATE IP (BLOCKED)" : "INVALID IOC";
            this.iocBadgeEl.className =
                "text-xs font-mono px-2.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800";
        }

        return outcome;
    }

    private async checkHealth(): Promise<void> {
        const badge: HTMLElement | null = document.getElementById("healthBadge");
        if (!badge) return;

        try {
            const response: Response = await fetch("/api/health");
            if (response.ok) {
                const payload: HealthApiResponse = (await response.json()) as HealthApiResponse;
                const cacheStatus: string = payload.redis_connected ? "Redis Active" : "Local Mode";
                badge.textContent = "Engine Online (" + cacheStatus + ")";
                badge.className =
                    "px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800";
            }
        } catch {
            badge.textContent = "Engine Offline";
            badge.className =
                "px-3 py-1 rounded-full text-xs font-semibold bg-rose-950 text-rose-300 border border-rose-800";
        }
    }

    private async refreshStats(): Promise<void> {
        try {
            const response: Response = await fetch("/api/stats");
            if (!response.ok) return;
            const payload: StatsApiResponse = (await response.json()) as StatsApiResponse;
            if (payload.status === "success") {
                const totalEl: HTMLElement | null = document.getElementById("statTotalScans");
                const avgEl: HTMLElement | null = document.getElementById("statAvgScore");
                const highEl: HTMLElement | null = document.getElementById("statHighRisk");
                if (totalEl) totalEl.textContent = String(payload.data.total_scans);
                if (avgEl) avgEl.textContent = String(payload.data.average_threat_score);
                if (highEl) highEl.textContent = String(payload.data.high_risk_detections);
            }
        } catch {
            return;
        }
    }

    private async executeAnalysis(): Promise<void> {
        const validation: ValidationOutcome = this.handleLiveValidation();
        this.errorAlertEl.classList.add("hidden");

        if (!validation.isValid) {
            this.errorAlertEl.textContent = validation.advisoryMessage;
            this.errorAlertEl.classList.remove("hidden");
            return;
        }

        this.targetInputEl.value = validation.normalizedTarget;
        this.submitBtnEl.disabled = true;
        this.resultAreaEl.classList.add("hidden");
        this.loadingEl.classList.remove("hidden");

        try {
            const response: Response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target: validation.normalizedTarget }),
            });

            if (!response.ok) {
                throw new Error("HTTP " + String(response.status));
            }

            const payload: AnalyzeApiResponse = (await response.json()) as AnalyzeApiResponse;
            if (payload.status === "success" && payload.data) {
                this.currentReport = payload.data;
                this.currentAnalytics = ThreatAnalyticsEngine.correlate(payload.data);
                this.renderAnalysisResult(payload.data, this.currentAnalytics, payload.cached);
                await Promise.all([this.refreshStats(), this.loadHistory()]);
            }
        } catch (err: unknown) {
            const msg: string = err instanceof Error ? err.message : "Unknown network error";
            this.errorAlertEl.textContent = "Reconnaissance request failed: " + msg;
            this.errorAlertEl.classList.remove("hidden");
        } finally {
            this.submitBtnEl.disabled = false;
            this.loadingEl.classList.add("hidden");
        }
    }

    private renderAnalysisResult(
        report: AnalysisReport,
        analytics: CorrelatedAnalytics,
        isCached: boolean
    ): void {
        const targetEl: HTMLElement | null = document.getElementById("resTarget");
        const resolvedIpEl: HTMLElement | null = document.getElementById("resResolvedIp");
        const scoreEl: HTMLElement | null = document.getElementById("resScore");
        const typeBadgeEl: HTMLElement | null = document.getElementById("resTypeBadge");
        const cacheBadgeEl: HTMLElement | null = document.getElementById("resCacheBadge");
        const riskBadgeEl: HTMLElement | null = document.getElementById("resRiskBadge");
        const breakdownEl: HTMLElement | null = document.getElementById("analyticsBreakdown");
        const summaryCardsEl: HTMLElement | null = document.getElementById("summaryCards");
        const jsonResultEl: HTMLElement | null = document.getElementById("jsonResult");

        if (targetEl) targetEl.textContent = report.target;
        if (resolvedIpEl) {
            resolvedIpEl.textContent =
                report.resolved_ip && report.resolved_ip !== report.target
                    ? "Resolved IPv4: " + report.resolved_ip
                    : "";
        }
        if (scoreEl) scoreEl.textContent = String(report.threat_score) + "/100";
        if (typeBadgeEl) typeBadgeEl.textContent = report.type;
        if (cacheBadgeEl) {
            cacheBadgeEl.textContent = isCached ? "REDIS CACHE HIT" : "LIVE TELEMETRY";
        }
        if (riskBadgeEl) {
            riskBadgeEl.textContent = analytics.riskLevel + " RISK";
            riskBadgeEl.className =
                "text-xs font-bold uppercase px-2.5 py-1 rounded " +
                DashboardComponents.getRiskBadgeStyle(analytics.riskLevel);
        }
        if (breakdownEl) {
            breakdownEl.innerHTML = DashboardComponents.renderPillars(analytics.pillars);
        }
        if (summaryCardsEl) {
            summaryCardsEl.innerHTML = DashboardComponents.renderSourceCards(report.results, analytics);
        }
        if (jsonResultEl) {
            jsonResultEl.textContent = JSON.stringify(report, null, 2);
        }

        this.resultAreaEl.classList.remove("hidden");
    }

    private async loadHistory(): Promise<void> {
        try {
            const response: Response = await fetch("/api/history?limit=30");
            if (!response.ok) return;
            const payload: HistoryApiResponse = (await response.json()) as HistoryApiResponse;
            if (payload.status === "success") {
                this.cachedHistory = payload.data;
                this.renderFilteredHistory();
            }
        } catch {
            this.historyAreaEl.innerHTML =
                '<p class="text-xs text-rose-400 text-center py-4">Failed to load audit history.</p>';
        }
    }

    private renderFilteredHistory(): void {
        const selectedCategory: HistoryFilterCategory =
            (this.historyFilterEl.value as HistoryFilterCategory) || "ALL";
        const searchQuery: string = this.historySearchEl.value.trim().toLowerCase();

        const filtered: HistoryRecordItem[] = this.cachedHistory.filter((item: HistoryRecordItem): boolean => {
            const matchesType: boolean = selectedCategory === "ALL" || item.type === selectedCategory;
            const matchesSearch: boolean = !searchQuery || item.target.toLowerCase().includes(searchQuery);
            return matchesType && matchesSearch;
        });

        this.historyAreaEl.innerHTML = DashboardComponents.renderHistoryItems(filtered);

        const rowElements: NodeListOf<HTMLElement> = this.historyAreaEl.querySelectorAll(".history-item");
        rowElements.forEach((row: HTMLElement): void => {
            row.addEventListener("click", async (): Promise<void> => {
                const targetToRescan: string = row.getAttribute("data-rescan") || "";
                if (targetToRescan) {
                    this.targetInputEl.value = targetToRescan;
                    this.handleLiveValidation();
                    window.scrollTo({ top: 0, behavior: "smooth" });
                    await this.executeAnalysis();
                }
            });
        });
    }
}

document.addEventListener("DOMContentLoaded", (): void => {
    const app: OSINTDashboardApp = new OSINTDashboardApp();
    void app.init();
});