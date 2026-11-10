import { TargetCategory, ValidationOutcome } from "./types.js";

export class IOCValidator {
    private static readonly IPV4_REGEX: RegExp =
        /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

    private static readonly EMAIL_REGEX: RegExp =
        /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}$/;

    private static readonly DOMAIN_REGEX: RegExp =
        /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}$/;

    public static refangIndicator(rawInput: string): { cleaned: string; wasModified: boolean } {
        const trimmed: string = rawInput.trim();
        let processed: string = trimmed
            .replace(/\[\.\]/g, ".")
            .replace(/\(\.\)/g, ".")
            .replace(/\[dot\]/gi, ".")
            .replace(/\[@\]/g, "@")
            .replace(/\[at\]/gi, "@")
            .replace(/^hxxps:\/\//i, "https://")
            .replace(/^hxxp:\/\//i, "http://");

        if (processed.startsWith("http://") || processed.startsWith("https://")) {
            try {
                const parsedUrl: URL = new URL(processed);
                processed = parsedUrl.hostname;
            } catch {
                processed = processed.replace(/^https?:\/\//i, "").split("/")[0] || processed;
            }
        } else if (processed.includes("/") && !processed.includes("@")) {
            processed = processed.split("/")[0] || processed;
        }

        if (processed.includes(":") && !processed.includes("@")) {
            const parts: string[] = processed.split(":");
            if (parts.length === 2 && /^\d+$/.test(parts[1] || "")) {
                processed = parts[0] || processed;
            }
        }

        const finalClean: string = processed.toLowerCase().trim();
        return {
            cleaned: finalClean,
            wasModified: finalClean !== trimmed.toLowerCase(),
        };
    }

    public static isPrivateOrReservedIpv4(ip: string): boolean {
        const octets: number[] = ip.split(".").map((part: string): number => parseInt(part, 10));
        if (octets.length !== 4 || octets.some((n: number): boolean => Number.isNaN(n))) {
            return false;
        }

        const first: number = octets[0] ?? 0;
        const second: number = octets[1] ?? 0;

        if (first === 0 || first === 10 || first === 127) {
            return true;
        }
        if (first === 100 && second >= 64 && second <= 127) {
            return true;
        }
        if (first === 169 && second === 254) {
            return true;
        }
        if (first === 172 && second >= 16 && second <= 31) {
            return true;
        }
        if (first === 192 && second === 168) {
            return true;
        }
        if (first >= 224) {
            return true;
        }
        return false;
    }

    public static inspect(rawInput: string): ValidationOutcome {
        if (!rawInput || rawInput.trim().length < 3) {
            return {
                isValid: false,
                normalizedTarget: "",
                detectedCategory: "invalid",
                isPrivateNetwork: false,
                wasDefanged: false,
                advisoryMessage: "Enter an IPv4 address, domain name, or email indicator.",
            };
        }

        const refanged = IOCValidator.refangIndicator(rawInput);
        const cleaned: string = refanged.cleaned;
        const wasModified: boolean = refanged.wasModified;

        if (IOCValidator.IPV4_REGEX.test(cleaned)) {
            const isPrivate: boolean = IOCValidator.isPrivateOrReservedIpv4(cleaned);
            if (isPrivate) {
                return {
                    isValid: false,
                    normalizedTarget: cleaned,
                    detectedCategory: "IPv4",
                    isPrivateNetwork: true,
                    wasDefanged: wasModified,
                    advisoryMessage: "RFC1918 / Reserved IPv4 detected. External OSINT requires a public routable IP.",
                };
            }
            return {
                isValid: true,
                normalizedTarget: cleaned,
                detectedCategory: "IPv4",
                isPrivateNetwork: false,
                wasDefanged: wasModified,
                advisoryMessage: wasModified
                    ? "Refanged IOC to public IPv4: " + cleaned
                    : "Valid public IPv4 indicator ready for BGP, Shodan & OTX reconnaissance.",
            };
        }

        if (IOCValidator.EMAIL_REGEX.test(cleaned)) {
            return {
                isValid: true,
                normalizedTarget: cleaned,
                detectedCategory: "email",
                isPrivateNetwork: false,
                wasDefanged: wasModified,
                advisoryMessage: wasModified
                    ? "Refanged IOC to Email: " + cleaned
                    : "Valid email identity ready for credential breach reconnaissance.",
            };
        }

        if (IOCValidator.DOMAIN_REGEX.test(cleaned)) {
            return {
                isValid: true,
                normalizedTarget: cleaned,
                detectedCategory: "domain",
                isPrivateNetwork: false,
                wasDefanged: wasModified,
                advisoryMessage: wasModified
                    ? "Extracted and refanged hostname: " + cleaned
                    : "Valid domain indicator ready for DNS resolution, Shodan & OTX reconnaissance.",
            };
        }

        return {
            isValid: false,
            normalizedTarget: cleaned,
            detectedCategory: "invalid",
            isPrivateNetwork: false,
            wasDefanged: wasModified,
            advisoryMessage: "Unrecognized IOC format. Expected public IPv4, registered domain, or email.",
        };
    }

    public static classifyQuick(target: string): TargetCategory {
        return IOCValidator.inspect(target).detectedCategory;
    }
}