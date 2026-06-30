import { XMLParser } from "fast-xml-parser";
import * as x509 from "@peculiar/x509";
import {
	GOOGLE_ROOT_PEM,
	AOSP_EC_ROOT_PEM,
	AOSP_RSA_ROOT_PEM,
	KNOX_ROOT_PEM,
} from "./constants";

export interface CertInfo {
	level: number;
	serialNumber: string;
	subject: string;
	issuer: string;
	notBefore: string;
	notAfter: string;
	isValid: boolean;
	isExpired: boolean;
}

export interface KeyboxResult {
	deviceId: string;
	algorithm: string;
	serialNumber: string;
	subject: string;
	certValid: boolean;
	certExpired: boolean;
	privateKeyMatch: boolean | null;
	chainValid: boolean;
	rootType: string;
	certCount: number;
	revoked: boolean;
	revokeReason?: string;
	checkTime: string;
	certInfos: CertInfo[];
}

interface KeyboxKey {
	"@_algorithm"?: string;
	PrivateKey: unknown;
	CertificateChain: {
		NumberOfCertificates: number;
		Certificate: unknown;
	};
}

interface KeyboxXml {
	AndroidAttestation: {
		Keybox: {
			"@_DeviceID"?: string;
			Key: KeyboxKey | KeyboxKey[];
		};
	};
}

function extractCertText(cert: unknown): string {
	let text = "";
	if (typeof cert === "string") {
		text = cert;
	} else if (cert && typeof cert === "object") {
		// fast-xml-parser with attributes: { "@_format": "pem", "#text": "..." }
		const obj = cert as Record<string, unknown>;
		if (typeof obj["#text"] === "string") text = obj["#text"];
	}
	if (!text) return "";
	// Remove leading whitespace from each line (XML indentation)
	return text.replace(/^\s+/gm, "").trim();
}

function parsePemCertificates(certField: unknown, count: number): string[] {
	if (Array.isArray(certField)) {
		return certField.slice(0, count).map(extractCertText).filter(Boolean);
	}
	const text = extractCertText(certField);
	if (!text) return [];
	const certs: string[] = [];
	const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
	let match: RegExpExecArray | null;
	while ((match = regex.exec(text)) !== null) {
		certs.push(match[0].trim());
	}
	return certs.slice(0, count);
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
	const base64 = pem
		.replace(/-----BEGIN PUBLIC KEY-----/, "")
		.replace(/-----END PUBLIC KEY-----/, "")
		.replace(/\s/g, "");
	const binary = atob(base64);
	const buffer = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		buffer[i] = binary.charCodeAt(i);
	}
	return buffer.buffer;
}

function arraysEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
	const ua = new Uint8Array(a);
	const ub = new Uint8Array(b);
	if (ua.length !== ub.length) return false;
	for (let i = 0; i < ua.length; i++) {
		if (ua[i] !== ub[i]) return false;
	}
	return true;
}

async function verifyChain(certs: x509.X509Certificate[]): Promise<boolean> {
	for (let i = 0; i < certs.length - 1; i++) {
		const child = certs[i];
		const parent = certs[i + 1];

		if (child.issuer !== parent.subject) {
			return false;
		}

		try {
			const valid = await child.verify({ publicKey: parent.publicKey });
			if (!valid) return false;
		} catch {
			return false;
		}
	}
	return true;
}

// DER encoding helpers for key format conversion
function encodeLengthDER(length: number): Uint8Array {
	if (length < 0x80) return new Uint8Array([length]);
	if (length < 0x100) return new Uint8Array([0x81, length]);
	if (length < 0x10000) return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
	throw new Error("DER length too large");
}

function wrapDER(tag: number, content: Uint8Array): Uint8Array {
	const len = encodeLengthDER(content.length);
	const result = new Uint8Array(1 + len.length + content.length);
	result[0] = tag;
	result.set(len, 1);
	result.set(content, 1 + len.length);
	return result;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
	const total = arrays.reduce((acc, a) => acc + a.length, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const a of arrays) {
		result.set(a, offset);
		offset += a.length;
	}
	return result;
}

/** Wrap PKCS#1 RSA private key DER into PKCS#8 */
function rsaPkcs1ToPkcs8(pkcs1Der: Uint8Array): ArrayBuffer {
	const version = new Uint8Array([0x02, 0x01, 0x00]);
	// OID 1.2.840.113549.1.1.1 (rsaEncryption)
	const rsaOid = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
	const nullVal = new Uint8Array([0x05, 0x00]);
	const algId = wrapDER(0x30, concatBytes(rsaOid, nullVal));
	const keyOctet = wrapDER(0x04, pkcs1Der);
	return wrapDER(0x30, concatBytes(version, algId, keyOctet)).buffer as ArrayBuffer;
}

/** Wrap SEC1 EC private key DER into PKCS#8 */
function ecSec1ToPkcs8(sec1Der: Uint8Array, namedCurve: string): ArrayBuffer {
	const version = new Uint8Array([0x02, 0x01, 0x00]);
	// OID 1.2.840.10045.2.1 (ecPublicKey)
	const ecOid = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
	let curveOid: Uint8Array;
	switch (namedCurve) {
		case "P-256":
			curveOid = new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
			break;
		case "P-384":
			curveOid = new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);
			break;
		case "P-521":
			curveOid = new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]);
			break;
		default:
			throw new Error(`Unsupported curve: ${namedCurve}`);
	}
	const algId = wrapDER(0x30, concatBytes(ecOid, curveOid));
	const keyOctet = wrapDER(0x04, sec1Der);
	return wrapDER(0x30, concatBytes(version, algId, keyOctet)).buffer as ArrayBuffer;
}

async function checkPrivateKeyMatch(
	privateKeyPem: string,
	cert: x509.X509Certificate,
): Promise<boolean> {
	try {
		const cleaned = privateKeyPem.replace(/^\s+/gm, "").trim();

		// Detect key format from PEM header
		const isRsaPkcs1 = cleaned.includes("BEGIN RSA PRIVATE KEY");
		const isEcSec1 = cleaned.includes("BEGIN EC PRIVATE KEY");

		const keyData = cleaned
			.replace(/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, "")
			.replace(/-----END (?:RSA |EC )?PRIVATE KEY-----/, "")
			.replace(/\s/g, "");

		const binaryKey = atob(keyData);
		const keyBuffer = new Uint8Array(binaryKey.length);
		for (let i = 0; i < binaryKey.length; i++) {
			keyBuffer[i] = binaryKey.charCodeAt(i);
		}

		const certPubKeyAlg = cert.publicKey.algorithm;
		const algName = (certPubKeyAlg as { name?: string }).name || "";

		let pkcs8Buffer: ArrayBuffer;
		let importAlg: { name: string; hash?: string; namedCurve?: string };

		if (algName.toUpperCase().includes("RSA")) {
			pkcs8Buffer = isRsaPkcs1 ? rsaPkcs1ToPkcs8(keyBuffer) : keyBuffer.buffer;
			importAlg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
		} else {
			const params = certPubKeyAlg as { namedCurve?: string };
			const namedCurve = params.namedCurve || "P-256";
			pkcs8Buffer = isEcSec1 ? ecSec1ToPkcs8(keyBuffer, namedCurve) : keyBuffer.buffer;
			importAlg = { name: "ECDSA", namedCurve };
		}

		const cryptoKey = await crypto.subtle.importKey(
			"pkcs8",
			pkcs8Buffer,
			importAlg,
			false,
			["sign"],
		);

		// Verify by signing test data with private key and verifying with cert public key
		const testData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
		let signAlg: { name: string; hash?: string };
		let verifyAlg: { name: string; hash?: string };
		if (algName.toUpperCase().includes("RSA")) {
			signAlg = { name: "RSASSA-PKCS1-v1_5" };
			verifyAlg = { name: "RSASSA-PKCS1-v1_5" };
		} else {
			signAlg = { name: "ECDSA", hash: "SHA-256" };
			verifyAlg = { name: "ECDSA", hash: "SHA-256" };
		}

		const signature = await crypto.subtle.sign(signAlg, cryptoKey, testData);

		const pubKey = await crypto.subtle.importKey(
			"spki",
			cert.publicKey.rawData,
			importAlg,
			false,
			["verify"],
		);

		return await crypto.subtle.verify(verifyAlg, pubKey, signature, testData);
	} catch {
		return false;
	}
}

function identifyRoot(rootCert: x509.X509Certificate): string {
	const rootSpki = rootCert.publicKey.rawData;

	if (arraysEqual(rootSpki, pemToArrayBuffer(GOOGLE_ROOT_PEM))) return "google";
	if (arraysEqual(rootSpki, pemToArrayBuffer(AOSP_EC_ROOT_PEM))) return "aosp_ec";
	if (arraysEqual(rootSpki, pemToArrayBuffer(AOSP_RSA_ROOT_PEM))) return "aosp_rsa";
	if (arraysEqual(rootSpki, pemToArrayBuffer(KNOX_ROOT_PEM))) return "knox";

	return "unknown";
}

interface RevokedEntry {
	reason: string;
}

interface StatusJson {
	entries: Record<string, RevokedEntry>;
}

async function fetchRevokedStatus(): Promise<StatusJson> {
	const url = `https://android.googleapis.com/attestation/status?ts=${Date.now()}`;
	const res = await fetch(url, {
		headers: {
			"Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
		},
	});
	if (!res.ok) throw new Error(`Failed to fetch revoked list: ${res.status}`);
	return res.json() as Promise<StatusJson>;
}

function formatDate(date: Date): string {
	return date.toISOString().replace("T", " ").slice(0, 19);
}

function extractCertInfo(cert: x509.X509Certificate, level: number): CertInfo {
	const now = new Date();
	const notBefore = cert.notBefore;
	const notAfter = cert.notAfter;
	return {
		level,
		serialNumber: cert.serialNumber.toLowerCase(),
		subject: cert.subject,
		issuer: cert.issuer,
		notBefore: formatDate(notBefore),
		notAfter: formatDate(notAfter),
		isValid: notBefore <= now && now <= notAfter,
		isExpired: now > notAfter,
	};
}

export async function checkKeybox(xmlContent: string): Promise<KeyboxResult> {
	const parser = new XMLParser({
		ignoreAttributes: false,
		attributeNamePrefix: "@_",
		isArray: (name) => name === "Certificate",
	});
	const parsed = parser.parse(xmlContent) as KeyboxXml;

	const keybox = parsed.AndroidAttestation?.Keybox;
	if (!keybox) throw new Error("Invalid Keybox XML: missing AndroidAttestation/Keybox");

	const deviceId = keybox["@_DeviceID"] || "Unknown";
	const rawKey = keybox.Key;
	if (!rawKey) throw new Error("Invalid Keybox XML: missing Key element");

	// Handle single or multiple Key elements - use the first one
	const key: KeyboxKey = Array.isArray(rawKey) ? rawKey[0] : rawKey;

	const algorithm = key["@_algorithm"] || "Unknown";
	const privateKeyPem = extractCertText(key.PrivateKey);
	const certChain = key.CertificateChain;
	if (!certChain) throw new Error("Invalid Keybox XML: missing CertificateChain");

	const pemNumber = certChain.NumberOfCertificates;
	const pemCertificates = parsePemCertificates(certChain.Certificate, pemNumber);

	if (pemCertificates.length === 0) {
		throw new Error("No certificates found in Keybox");
	}

	const certs = pemCertificates.map((pem) => new x509.X509Certificate(pem));

	const leafCert = certs[0];
	const serialNumber = leafCert.serialNumber.toLowerCase();
	const subject = leafCert.subject;

	const now = new Date();
	const certValid = leafCert.notBefore <= now && now <= leafCert.notAfter;
	const certExpired = now > leafCert.notAfter;

	let privateKeyMatch: boolean | null = null;
	if (privateKeyPem) {
		privateKeyMatch = await checkPrivateKeyMatch(privateKeyPem, leafCert);
	}

	const chainValid = certs.length > 1 ? await verifyChain(certs) : true;

	const rootCert = certs[certs.length - 1];
	const rootType = identifyRoot(rootCert);

	// Extract info for each cert level
	const certInfos = certs.map((cert, i) => extractCertInfo(cert, i));

	// Revocation check
	let revoked = false;
	let revokeReason: string | undefined;
	try {
		const statusJson = await fetchRevokedStatus();
		for (const cert of certs) {
			const sn = cert.serialNumber.toLowerCase();
			const entry = statusJson.entries[sn];
			if (entry) {
				revoked = true;
				revokeReason = entry.reason;
				break;
			}
		}
	} catch {
		revokeReason = "⚠️ Failed to fetch revoked list";
	}

	const checkTime = formatDate(new Date());

	return {
		deviceId,
		algorithm,
		serialNumber,
		subject,
		certValid,
		certExpired,
		privateKeyMatch,
		chainValid,
		rootType,
		certCount: pemCertificates.length,
		revoked,
		revokeReason,
		checkTime,
		certInfos,
	};
}

export function formatResult(result: KeyboxResult): string {
	let reply = `📱 <b>Device ID:</b> <code>${escapeHtml(result.deviceId)}</code>`;
	reply += `\n🔑 <b>Algorithm:</b> <code>${escapeHtml(result.algorithm)}</code>`;
	reply += `\n────────────────────`;
	reply += `\n🔐 <b>Serial Number:</b> <code>${escapeHtml(result.serialNumber)}</code>`;
	reply += `\nℹ️ <b>Subject:</b> <code>${escapeHtml(result.subject)}</code>`;

	if (result.certValid) {
		reply += `\n✅ Certificate within validity period`;
	} else if (result.certExpired) {
		reply += `\n❌ Expired certificate`;
	} else {
		reply += `\n❌ Certificate not yet valid`;
	}

	if (result.privateKeyMatch === true) {
		reply += `\n✅ Matching private key and certificate public key`;
	} else if (result.privateKeyMatch === false) {
		reply += `\n❌ Mismatched private key and certificate public key`;
	} else {
		reply += `\n❌ Invalid private key`;
	}

	if (result.chainValid) {
		reply += `\n✅ Valid certificate chain`;
	} else {
		reply += `\n❌ Invalid certificate chain`;
	}

	switch (result.rootType) {
		case "google":
			reply += `\n✅ Google hardware attestation root certificate`;
			break;
		case "aosp_ec":
			reply += `\n🟡 AOSP software attestation root certificate (EC)`;
			break;
		case "aosp_rsa":
			reply += `\n🟡 AOSP software attestation root certificate (RSA)`;
			break;
		case "knox":
			reply += `\n✅ Samsung Knox attestation root certificate`;
			break;
		default:
			reply += `\n❌ Unknown root certificate`;
	}

	if (result.certCount >= 4) {
		reply += `\n🟡 More than 3 certificates in the chain`;
	}

	if (result.revoked) {
		reply += `\n❌ Serial number found in Google's revoked keybox list`;
		if (result.revokeReason) {
			reply += `\n🔍 <b>Reason:</b> <code>${escapeHtml(result.revokeReason)}</code>`;
		}
	} else if (result.revokeReason?.startsWith("⚠️")) {
		reply += `\n${result.revokeReason}`;
	} else {
		reply += `\n✅ Serial number not found in Google's revoked keybox list`;
	}

	reply += `\n⏱ <b>Check Time (UTC):</b> ${result.checkTime}`;
	return reply;
}

export function formatCertDetail(info: CertInfo, totalCount: number): string {
	const levelLabel = info.level === 0 ? "Leaf" : info.level === totalCount - 1 ? "Root" : `Intermediate ${info.level}`;
	let reply = `🔗 <b>Certificate Level ${info.level} (${levelLabel})</b>`;
	reply += `\n────────────────────`;
	reply += `\n🔐 <b>Serial Number:</b> <code>${escapeHtml(info.serialNumber)}</code>`;
	reply += `\nℹ️ <b>Subject:</b> <code>${escapeHtml(info.subject)}</code>`;
	reply += `\n📤 <b>Issuer:</b> <code>${escapeHtml(info.issuer)}</code>`;
	reply += `\n📅 <b>Not Before:</b> <code>${info.notBefore}</code>`;
	reply += `\n📅 <b>Not After:</b> <code>${info.notAfter}</code>`;

	if (info.isValid) {
		reply += `\n✅ Within validity period`;
	} else if (info.isExpired) {
		reply += `\n❌ Expired`;
	} else {
		reply += `\n❌ Not yet valid`;
	}

	return reply;
}

export function escapeHtml(text: string): string {
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}
