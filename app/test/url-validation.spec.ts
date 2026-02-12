/**
 * URL Validation Security Tests
 * 
 * This test suite verifies that the SSRF protection in url-validation.ts
 * correctly blocks malicious URLs while allowing legitimate requests.
 */

import { describe, it, expect } from 'vitest';
import {
	validateUrl,
	validateUrlOrThrow,
	isUrlSafe,
	validateUrls,
	createValidationErrorResponse,
	getBlockedIPRanges,
	getBlockedHostnames,
} from '../src/url-validation';

describe('URL Validation - SSRF Protection', () => {
	describe('RFC 1918 Private IP Ranges', () => {
		it('should block Class A private (10.0.0.0/8)', () => {
			const result = validateUrl('http://10.0.0.1/admin');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('10.0.0.0/8');
			expect(result.category).toBe('IP_RANGE');
		});

		it('should block Class B private (172.16.0.0/12)', () => {
			const result = validateUrl('http://172.16.0.1:8080');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('172.16.0.0/12');
		});

		it('should block Class C private (192.168.0.0/16)', () => {
			const result = validateUrl('http://192.168.1.1');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('192.168.0.0/16');
		});

		it('should allow public IP addresses', () => {
			const result = validateUrl('http://8.8.8.8');
			expect(result.valid).toBe(true);
			expect(result.normalizedUrl).toBe('http://8.8.8.8/');
		});

		it('should allow 1.1.1.1 (public IP)', () => {
			const result = validateUrl('http://1.1.1.1');
			expect(result.valid).toBe(true);
		});
	});

	describe('Loopback and Localhost', () => {
		it('should block localhost', () => {
			const result = validateUrl('http://localhost/admin');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('localhost');
			expect(result.category).toBe('HOSTNAME');
		});

		it('should block 127.0.0.1', () => {
			const result = validateUrl('http://127.0.0.1');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('127.0.0.0/8');
		});

		it('should block 127.0.0.53', () => {
			const result = validateUrl('http://127.0.0.53');
			expect(result.valid).toBe(false);
		});

		it('should block IPv6 loopback ::1', () => {
			const result = validateUrl('http://[::1]');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('IPv6 loopback');
		});
	});

	describe('Cloud Metadata Endpoints', () => {
		it('should block AWS metadata (169.254.169.254)', () => {
			const result = validateUrl('http://169.254.169.254/latest/meta-data/');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('169.254.169.254');
			expect(result.category).toBe('IP_RANGE');
		});

		it('should block GCP metadata', () => {
			const result = validateUrl('http://metadata.google.internal/computeMetadata/v1/');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('Cloud metadata');
		});

		it('should block Azure metadata', () => {
			const result = validateUrl('http://169.254.169.254/metadata/v1/');
			expect(result.valid).toBe(false);
		});
	});

	describe('URL Schemes', () => {
		it('should allow http://', () => {
			const result = validateUrl('http://example.com');
			expect(result.valid).toBe(true);
			expect(result.normalizedUrl).toBe('http://example.com/');
		});

		it('should allow https://', () => {
			const result = validateUrl('https://example.com');
			expect(result.valid).toBe(true);
			expect(result.normalizedUrl).toBe('https://example.com/');
		});

		it('should block file://', () => {
			const result = validateUrl('file:///etc/passwd');
			expect(result.valid).toBe(false);
			expect(result.category).toBe('PROTOCOL');
		});

		it('should block ftp://', () => {
			const result = validateUrl('ftp://example.com');
			expect(result.valid).toBe(false);
			expect(result.category).toBe('PROTOCOL');
		});

		it('should block data://', () => {
			const result = validateUrl('data:text/html,<script>alert(1)</script>');
			expect(result.valid).toBe(false);
			expect(result.category).toBe('PROTOCOL');
		});

		it('should block javascript://', () => {
			const result = validateUrl('javascript:alert(1)');
			expect(result.valid).toBe(false);
			expect(result.category).toBe('PROTOCOL');
		});

		it('should block ws://', () => {
			const result = validateUrl('ws://example.com');
			expect(result.valid).toBe(false);
			expect(result.category).toBe('PROTOCOL');
		});
	});

	describe('Encoded IP Addresses', () => {
		it('should block decimal-encoded IP (127.0.0.1 = 2130706433)', () => {
			const result = validateUrl('http://2130706433');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('decimal format');
		});

		it('should block hex-encoded IP', () => {
			const result = validateUrl('http://0x7f000001');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('hexadecimal format');
		});

		it('should block octal-encoded IP', () => {
			const result = validateUrl('http://0177.0.0.1');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('octal format');
		});
	});

	describe('Reserved and Special IP Ranges', () => {
		it('should block multicast (224.0.0.0/4)', () => {
			const result = validateUrl('http://224.0.0.1');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('Multicast');
		});

		it('should block 0.0.0.0 (all interfaces)', () => {
			const result = validateUrl('http://0.0.0.0');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('All interfaces');
		});

		it('should block link-local (169.254.1.1)', () => {
			const result = validateUrl('http://169.254.1.1');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('Link-local');
		});
	});

	describe('Blocked Hostname Patterns', () => {
		it('should block .local domains', () => {
			const result = validateUrl('http://myserver.local');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('mDNS/Bonjour');
		});

		it('should block .internal domains', () => {
			const result = validateUrl('http://internal.service');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('Internal network');
		});
	});

	describe('Valid URLs', () => {
		it('should allow valid HTTPS URLs', () => {
			const result = validateUrl('https://example.com');
			expect(result.valid).toBe(true);
			expect(result.normalizedUrl).toBe('https://example.com/');
		});

		it('should allow valid HTTP URLs', () => {
			const result = validateUrl('http://example.com');
			expect(result.valid).toBe(true);
			expect(result.normalizedUrl).toBe('http://example.com/');
		});

		it('should allow URLs with ports', () => {
			const result = validateUrl('https://example.com:8443');
			expect(result.valid).toBe(true);
			expect(result.normalizedUrl).toBe('https://example.com:8443/');
		});

		it('should allow URLs with paths', () => {
			const result = validateUrl('https://example.com/path/to/resource');
			expect(result.valid).toBe(true);
			expect(result.normalizedUrl).toBe('https://example.com/path/to/resource');
		});

		it('should allow URLs with query params', () => {
			const result = validateUrl('https://example.com?param=value');
			expect(result.valid).toBe(true);
			expect(result.normalizedUrl).toBe('https://example.com/?param=value');
		});

		it('should auto-add https:// when missing', () => {
			const result = validateUrl('example.com');
			expect(result.valid).toBe(true);
			expect(result.normalizedUrl).toBe('https://example.com/');
		});

		it('should allow subdomains', () => {
			const result = validateUrl('https://api.example.com');
			expect(result.valid).toBe(true);
		});

		it('should allow international domains', () => {
			const result = validateUrl('https://例子.测试');
			expect(result.valid).toBe(true);
		});
	});

	describe('Input Validation', () => {
		it('should reject empty URLs', () => {
			const result = validateUrl('');
			expect(result.valid).toBe(false);
			expect(result.errorCode).toBe('EMPTY_URL');
		});

		it('should reject whitespace-only URLs', () => {
			const result = validateUrl('   ');
			expect(result.valid).toBe(false);
			expect(result.errorCode).toBe('EMPTY_URL');
		});

		it('should reject excessively long URLs', () => {
			const longUrl = 'https://example.com/' + 'a'.repeat(2100);
			const result = validateUrl(longUrl);
			expect(result.valid).toBe(false);
			expect(result.errorCode).toBe('URL_TOO_LONG');
		});

		it('should reject malformed URLs', () => {
			const result = validateUrl('not a url');
			expect(result.valid).toBe(false);
			expect(result.errorCode).toBe('INVALID_URL_FORMAT');
		});

		it('should reject URLs with double dots', () => {
			const result = validateUrl('http://example..com');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('Invalid hostname format');
		});
	});
});

describe('validateUrlOrThrow', () => {
	it('should return normalized URL for valid input', () => {
		const result = validateUrlOrThrow('https://example.com');
		expect(result).toBe('https://example.com/');
	});

	it('should throw for blocked IP', () => {
		expect(() => validateUrlOrThrow('http://127.0.0.1')).toThrow('Blocked IP address');
	});

	it('should throw for blocked protocol', () => {
		expect(() => validateUrlOrThrow('file:///etc/passwd')).toThrow('Blocked URL scheme');
	});
});

describe('isUrlSafe', () => {
	it('should return true for safe URLs', () => {
		expect(isUrlSafe('https://example.com')).toBe(true);
		expect(isUrlSafe('http://example.com')).toBe(true);
	});

	it('should return false for unsafe URLs', () => {
		expect(isUrlSafe('http://localhost')).toBe(false);
		expect(isUrlSafe('http://10.0.0.1')).toBe(false);
		expect(isUrlSafe('file:///etc/passwd')).toBe(false);
	});
});

describe('validateUrls', () => {
	it('should validate multiple URLs', () => {
		const results = validateUrls([
			'https://example.com',
			'http://127.0.0.1',
			'https://10.0.0.1',
		]);

		expect(results).toHaveLength(3);
		expect(results[0].valid).toBe(true);
		expect(results[1].valid).toBe(false);
		expect(results[2].valid).toBe(false);
	});

	it('should return all validation results', () => {
		const results = validateUrls(['https://a.com', 'https://b.com']);

		expect(results.every(r => r.valid)).toBe(true);
	});
});

describe('createValidationErrorResponse', () => {
	it('should create standardized error response', () => {
		const result = validateUrl('http://127.0.0.1');
		const errorResponse = createValidationErrorResponse(result);

		expect(errorResponse).toHaveProperty('error');
		expect(errorResponse).toHaveProperty('message');
		expect(errorResponse).toHaveProperty('errorCode');
		expect(errorResponse).toHaveProperty('category');
		expect(errorResponse.error).toBe('Invalid URL');
	});
});

describe('getBlockedIPRanges', () => {
	it('should return list of blocked IP ranges', () => {
		const ranges = getBlockedIPRanges();

		expect(Array.isArray(ranges)).toBe(true);
		expect(ranges.length).toBeGreaterThan(0);
		expect(ranges.some(r => r.name.includes('RFC 1918'))).toBe(true);
	});

	it('should include all expected ranges', () => {
		const ranges = getBlockedIPRanges();
		const rangeNames = ranges.map(r => r.name);

		expect(rangeNames).toContain('RFC 1918 - Class A Private (10.0.0.0/8)');
		expect(rangeNames).toContain('RFC 1918 - Class B Private (172.16.0.0/12)');
		expect(rangeNames).toContain('RFC 1918 - Class C Private (192.168.0.0/16)');
		expect(rangeNames).toContain('Loopback (127.0.0.0/8)');
		expect(rangeNames).toContain('Link-local (169.254.0.0/16) - Cloud Metadata');
	});
});

describe('getBlockedHostnames', () => {
	it('should return list of blocked hostnames', () => {
		const hostnames = getBlockedHostnames();

		expect(Array.isArray(hostnames)).toBe(true);
		expect(hostnames.length).toBeGreaterThan(0);
	});

	it('should include localhost', () => {
		const hostnames = getBlockedHostnames();
		expect(hostnames.some(h => h.name === 'localhost')).toBe(true);
	});

	it('should include .local pattern', () => {
		const hostnames = getBlockedHostnames();
		expect(hostnames.some(h => h.name === 'mDNS/Bonjour local hostname')).toBe(true);
	});
});

describe('Real-world SSRF Attack Vectors', () => {
	it('should block AWS metadata access', () => {
		const result = validateUrl('http://169.254.169.254/latest/meta-data/iam/security-credentials/');
		expect(result.valid).toBe(false);
	});

	it('should block GCP metadata access', () => {
		const result = validateUrl('http://metadata.google.internal/computeMetadata/v1/project/project-id');
		expect(result.valid).toBe(false);
	});

	it('should block Azure metadata access', () => {
		const result = validateUrl('http://169.254.169.254/metadata/identity?api-version=2019-03-01');
		expect(result.valid).toBe(false);
	});

	it('should block internal network scanning (10.0.0.0/8)', () => {
		const result = validateUrl('http://10.0.0.1:8080');
		expect(result.valid).toBe(false);
	});

	it('should block internal network scanning (172.16.0.0/12)', () => {
		const result = validateUrl('http://172.31.255.255');
		expect(result.valid).toBe(false);
	});

	it('should block internal network scanning (192.168.0.0/16)', () => {
		const result = validateUrl('http://192.168.1.254');
		expect(result.valid).toBe(false);
	});

	it('should block localhost exploitation', () => {
		const result = validateUrl('http://localhost:6379');
		expect(result.valid).toBe(false);
	});

	it('should block file:// protocol for local file access', () => {
		const result = validateUrl('file:///etc/passwd');
		expect(result.valid).toBe(false);
	});

	it('should block DNS rebinding attempts', () => {
		const result = validateUrl('http://127.0.53.1');
		expect(result.valid).toBe(false);
	});
});
