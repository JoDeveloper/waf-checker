/**
 * URL Validation Utility with SSRF Protection
 * 
 * This module provides comprehensive URL validation to prevent Server-Side Request Forgery (SSRF)
 * attacks by blocking access to internal networks, localhost, and cloud metadata endpoints.
 * 
 * Security Features:
 * - Blocks RFC 1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
 * - Blocks localhost and loopback addresses (127.0.0.0/8, ::1)
 * - Blocks cloud metadata IPs (169.254.169.254, link-local 169.254.0.0/16)
 * - Blocks multicast and reserved IP ranges
 * - Restricts URL schemes to http:// and https:// only
 * - Validates URL format and encoding
 * - Provides detailed error messages for security auditing
 */

/**
 * Validation result with detailed error information
 */
export interface ValidationResult {
	/** Whether the URL passed all security checks */
	valid: boolean;
	/** Human-readable error message explaining why validation failed */
	error?: string;
	/** Error code for programmatic handling */
	errorCode?: string;
	/** The normalized URL if validation succeeded */
	normalizedUrl?: string;
	/** Security category of the violation */
	category?: 'PROTOCOL' | 'IP_RANGE' | 'HOSTNAME' | 'FORMAT' | 'BLOCKED';
}

/**
 * Blocked IP range configuration
 */
interface BlockedRange {
	/** Name of the blocked range */
	name: string;
	/** Check function that returns true if IP is in this range */
	check: (ip: string) => boolean;
	/** Security category */
	category: 'IP_RANGE';
}

/**
 * Blocked hostname patterns
 */
interface BlockedHostname {
	/** Pattern to match (regex or string) */
	pattern: RegExp | string;
	/** Name of the blocked hostname */
	name: string;
	/** Security category */
	category: 'HOSTNAME';
}

/**
 * List of blocked IP ranges for SSRF protection
 */
const BLOCKED_IP_RANGES: BlockedRange[] = [
	{
		name: 'RFC 1918 - Class A Private (10.0.0.0/8)',
		check: (ip: string) => /^10\./.test(ip),
		category: 'IP_RANGE',
	},
	{
		name: 'RFC 1918 - Class B Private (172.16.0.0/12)',
		check: (ip: string) => /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip),
		category: 'IP_RANGE',
	},
	{
		name: 'RFC 1918 - Class C Private (192.168.0.0/16)',
		check: (ip: string) => /^192\.168\./.test(ip),
		category: 'IP_RANGE',
	},
	{
		name: 'Loopback (127.0.0.0/8)',
		check: (ip: string) => /^127\./.test(ip),
		category: 'IP_RANGE',
	},
	{
		name: 'Link-local (169.254.0.0/16) - Cloud Metadata',
		check: (ip: string) => /^169\.254\./.test(ip),
		category: 'IP_RANGE',
	},
	{
		name: 'Link-local (169.254.169.254) - AWS/GCP/Azure Metadata',
		check: (ip: string) => ip === '169.254.169.254',
		category: 'IP_RANGE',
	},
	{
		name: 'Multicast (224.0.0.0/4)',
		check: (ip: string) => /^22[4-9]\./.test(ip) || /^23[0-9]\./.test(ip),
		category: 'IP_RANGE',
	},
	{
		name: 'Reserved (240.0.0.0/4)',
		check: (ip: string) => /^24[0-9]\./.test(ip) || /^25[0-5]\./.test(ip),
		category: 'IP_RANGE',
	},
	{
		name: 'Carrier-grade NAT (100.64.0.0/10)',
		check: (ip: string) => /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(ip),
		category: 'IP_RANGE',
	},
	{
		name: 'Benchmarking (198.18.0.0/15)',
		check: (ip: string) => /^198\.(18|19)\./.test(ip),
		category: 'IP_RANGE',
	},
];

/**
 * List of blocked hostname patterns
 */
const BLOCKED_HOSTNAMES: BlockedHostname[] = [
	{
		pattern: /^localhost$/i,
		name: 'localhost',
		category: 'HOSTNAME',
	},
	{
		pattern: /^127\.\d+\.\d+\.\d+$/,
		name: 'Loopback IP',
		category: 'HOSTNAME',
	},
	{
		pattern: /^0\.0\.0\.0$/,
		name: 'All interfaces',
		category: 'HOSTNAME',
	},
	{
		pattern: /^metadata$/i,
		name: 'Cloud metadata hostname',
		category: 'HOSTNAME',
	},
	{
		pattern: /\.local$/i,
		name: 'mDNS/Bonjour local hostname',
		category: 'HOSTNAME',
	},
	{
		pattern: /\.internal$/i,
		name: 'Internal network hostname',
		category: 'HOSTNAME',
	},
];

/**
 * Allowed URL schemes
 */
const ALLOWED_SCHEMES = ['http:', 'https:'] as const;

/**
 * Blocked URL schemes
 */
const BLOCKED_SCHEMES = ['file:', 'ftp:', 'data:', 'javascript:', 'mailto:', 'tel:', 'ws:', 'wss:'] as const;

/**
 * Validates if a string is a valid IPv4 address
 */
function isValidIPv4(ip: string): boolean {
	const parts = ip.split('.');
	if (parts.length !== 4) return false;
	return parts.every(part => {
		const num = parseInt(part, 10);
		return !isNaN(num) && num >= 0 && num <= 255 && part === num.toString();
	});
}

/**
 * Checks if an IPv4 address is in any blocked range
 */
function isBlockedIPv4(ip: string): { blocked: boolean; reason?: string } {
	for (const range of BLOCKED_IP_RANGES) {
		if (range.check(ip)) {
			return { blocked: true, reason: range.name };
		}
	}
	return { blocked: false };
}

/**
 * Checks if a hostname matches any blocked pattern
 */
function isBlockedHostname(hostname: string): { blocked: boolean; reason?: string } {
	for (const blocked of BLOCKED_HOSTNAMES) {
		if (blocked.pattern instanceof RegExp) {
			if (blocked.pattern.test(hostname)) {
				return { blocked: true, reason: blocked.name };
			}
		} else {
			if (hostname === blocked.pattern) {
				return { blocked: true, reason: blocked.name };
			}
		}
	}
	return { blocked: false };
}

/**
 * Validates a URL string and returns a detailed validation result
 * 
 * @param urlString - The URL string to validate
 * @returns ValidationResult with validation status and error details
 * 
 * @example
 * ```typescript
 * const result = validateUrl('https://example.com');
 * if (result.valid) {
 *   console.log('URL is safe:', result.normalizedUrl);
 * } else {
 *   console.error('Validation failed:', result.error);
 * }
 * ```
 */
export function validateUrl(urlString: string): ValidationResult {
	// Trim whitespace
	urlString = urlString.trim();

	// Check for empty input
	if (!urlString) {
		return {
			valid: false,
			error: 'URL parameter is empty',
			errorCode: 'EMPTY_URL',
			category: 'FORMAT',
		};
	}

	// Check for excessive length (potential DoS vector)
	if (urlString.length > 2048) {
		return {
			valid: false,
			error: 'URL exceeds maximum length of 2048 characters',
			errorCode: 'URL_TOO_LONG',
			category: 'FORMAT',
		};
	}

	// Try to parse the URL
	let url: URL;
	try {
		url = new URL(urlString);
	} catch (e) {
		// Try adding https:// if missing protocol
		if (!urlString.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:/)) {
			try {
				url = new URL(`https://${urlString}`);
			} catch {
				return {
					valid: false,
					error: 'Invalid URL format',
					errorCode: 'INVALID_URL_FORMAT',
					category: 'FORMAT',
				};
			}
		} else {
			return {
				valid: false,
				error: 'Invalid URL format',
				errorCode: 'INVALID_URL_FORMAT',
				category: 'FORMAT',
			};
		}
	}

	// Check protocol
	const protocol = url.protocol.toLowerCase();
	if (BLOCKED_SCHEMES.includes(protocol as any)) {
		return {
			valid: false,
			error: `Blocked URL scheme: ${protocol}`,
			errorCode: 'BLOCKED_SCHEME',
			category: 'PROTOCOL',
		};
	}

	if (!ALLOWED_SCHEMES.includes(protocol as any)) {
		return {
			valid: false,
			error: `Unsupported URL scheme: ${protocol}. Only http:// and https:// are allowed`,
			errorCode: 'UNSUPPORTED_SCHEME',
			category: 'PROTOCOL',
		};
	}

	// Extract hostname (remove port if present)
	const hostname = url.hostname.toLowerCase();

	// Check for blocked hostnames
	const hostnameCheck = isBlockedHostname(hostname);
	if (hostnameCheck.blocked) {
		return {
			valid: false,
			error: `Blocked hostname: ${hostnameCheck.reason}`,
			errorCode: 'BLOCKED_HOSTNAME',
			category: 'HOSTNAME',
		};
	}

	// Check if hostname is an IPv4 address
	if (isValidIPv4(hostname)) {
		const ipCheck = isBlockedIPv4(hostname);
		if (ipCheck.blocked) {
			return {
				valid: false,
				error: `Blocked IP address: ${ipCheck.reason}`,
				errorCode: 'BLOCKED_IP_RANGE',
				category: 'IP_RANGE',
			};
		}
	}

	// Check for IPv6 loopback (::1)
	if (hostname === '::1' || hostname === '[::1]') {
		return {
			valid: false,
			error: 'Blocked IPv6 loopback address',
			errorCode: 'BLOCKED_IPV6_LOOPBACK',
			category: 'IP_RANGE',
		};
	}

	// Check for IPv6 link-local (fe80::/10)
	if (hostname.startsWith('fe80:') || hostname.startsWith('[fe80:')) {
		return {
			valid: false,
			error: 'Blocked IPv6 link-local address',
			errorCode: 'BLOCKED_IPV6_LINK_LOCAL',
			category: 'IP_RANGE',
		};
	}

	// Check for encoded IP addresses (e.g., decimal, hex, octal)
	// This prevents bypass attempts like http://2130706433 (127.0.0.1 in decimal)
	if (/^\d+$/.test(hostname)) {
		return {
			valid: false,
			error: 'Blocked: IP address in decimal format',
			errorCode: 'ENCODED_IP_DECIMAL',
			category: 'IP_RANGE',
		};
	}

	// Check for hex-encoded IP
	if (/^0x[0-9a-f]+$/i.test(hostname)) {
		return {
			valid: false,
			error: 'Blocked: IP address in hexadecimal format',
			errorCode: 'ENCODED_IP_HEX',
			category: 'IP_RANGE',
		};
	}

	// Check for octal-encoded IP
	if (/^0[0-7]+$/i.test(hostname)) {
		return {
			valid: false,
			error: 'Blocked: IP address in octal format',
			errorCode: 'ENCODED_IP_OCTAL',
			category: 'IP_RANGE',
		};
	}

	// Check for potential DNS rebinding attacks (multiple dots in unusual patterns)
	if (hostname.includes('..') || hostname.startsWith('.') || hostname.endsWith('.')) {
		return {
			valid: false,
			error: 'Invalid hostname format',
			errorCode: 'INVALID_HOSTNAME_FORMAT',
			category: 'FORMAT',
		};
	}

	// Return success with normalized URL
	return {
		valid: true,
		normalizedUrl: url.toString(),
	};
}

/**
 * Validates a URL and throws an error if validation fails
 * 
 * @param urlString - The URL string to validate
 * @returns The normalized URL if validation succeeds
 * @throws Error with validation details if validation fails
 * 
 * @example
 * ```typescript
 * try {
 *   const url = validateUrlOrThrow('https://example.com');
 *   // Safe to use the URL
 *   await fetch(url);
 * } catch (e) {
 *   console.error('URL validation failed:', e.message);
 * }
 * ```
 */
export function validateUrlOrThrow(urlString: string): string {
	const result = validateUrl(urlString);
	if (!result.valid) {
		const error = new Error(result.error || 'URL validation failed');
		(error as any).code = result.errorCode;
		(error as any).category = result.category;
		throw error;
	}
	return result.normalizedUrl!;
}

/**
 * Batch validates multiple URLs
 * 
 * @param urls - Array of URL strings to validate
 * @returns Array of validation results
 * 
 * @example
 * ```typescript
 * const results = validateUrls([
 *   'https://example.com',
 *   'http://127.0.0.1/admin',
 *   'https://169.254.169.254/latest/meta-data/'
 * ]);
 * const validUrls = results.filter(r => r.valid).map(r => r.normalizedUrl);
 * ```
 */
export function validateUrls(urls: string[]): ValidationResult[] {
	return urls.map(url => validateUrl(url));
}

/**
 * Checks if a URL is safe without throwing errors
 * 
 * @param urlString - The URL string to check
 * @returns true if the URL is safe, false otherwise
 * 
 * @example
 * ```typescript
 * if (isUrlSafe(userInput)) {
 *   await fetch(userInput);
 * } else {
 *   return new Response('Invalid URL', { status: 400 });
 * }
 * ```
 */
export function isUrlSafe(urlString: string): boolean {
	return validateUrl(urlString).valid;
}

/**
 * Gets a list of all blocked IP ranges for documentation
 */
export function getBlockedIPRanges(): Array<{ name: string; category: string }> {
	return BLOCKED_IP_RANGES.map(range => ({
		name: range.name,
		category: range.category,
	}));
}

/**
 * Gets a list of all blocked hostname patterns for documentation
 */
export function getBlockedHostnames(): Array<{ name: string; pattern: string; category: string }> {
	return BLOCKED_HOSTNAMES.map(host => ({
		name: host.name,
		pattern: host.pattern instanceof RegExp ? host.pattern.source : host.pattern,
		category: host.category,
	}));
}

/**
 * Creates a standardized error response for URL validation failures
 * 
 * @param result - The validation result
 * @returns An object suitable for JSON error responses
 */
export function createValidationErrorResponse(result: ValidationResult): {
	error: string;
	message: string;
	errorCode: string;
	category: string;
} {
	return {
		error: 'Invalid URL',
		message: result.error || 'URL validation failed',
		errorCode: result.errorCode || 'UNKNOWN',
		category: result.category || 'UNKNOWN',
	};
}
