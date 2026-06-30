import "reflect-metadata";
import { TelegramBot, type TelegramUpdate, type TelegramMessage, type InlineKeyboardButton } from "./telegram";
import { checkKeybox, formatResult, formatCertDetail, type KeyboxResult } from "./keybox";

export interface Env {
	BOT_TOKEN: string;
	BOT_SECRET: string;
	KV: KVNamespace;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname === "/register" && request.method === "GET") {
			const bot = new TelegramBot(env.BOT_TOKEN);
			const webhookUrl = `${url.origin}/webhook/${env.BOT_SECRET}`;
			const ok = await bot.setWebhook(webhookUrl);
			return new Response(ok ? "Webhook set successfully" : "Failed to set webhook", {
				status: ok ? 200 : 500,
			});
		}

		if (url.pathname === `/webhook/${env.BOT_SECRET}` && request.method === "POST") {
			const update = (await request.json()) as TelegramUpdate;
			await handleUpdate(update, env);
			return new Response("OK");
		}

		return new Response("Not Found", { status: 404 });
	},
};

async function handleUpdate(update: TelegramUpdate, env: Env): Promise<void> {
	const bot = new TelegramBot(env.BOT_TOKEN);

	// Handle callback queries (inline button presses)
	if (update.callback_query) {
		await handleCallback(bot, update.callback_query, env);
		return;
	}

	// Handle guest messages (bot not in chat, user @mentioned it)
	if (update.guest_message) {
		await handleGuestMessage(bot, update.guest_message, env);
		return;
	}

	const message = update.message;
	if (!message) return;

	const chatId = message.chat.id;

	// Handle /start command
	if (message.text?.startsWith("/start")) {
		await bot.sendMessage(
			chatId,
			"👋 Send me a <code>keybox.xml</code> file or reply to one with /keybox to verify it.",
			message.message_id,
		);
		return;
	}

	// Handle /keybox command
	if (message.text?.match(/^\/keybox(?:@\w+)?(?:\s|$)/)) {
		const args = message.text.replace(/^\/keybox(?:@\w+)?\s*/, "").trim();

		// If a URL is provided, fetch from remote
		if (args && /^https?:\/\/.+/i.test(args)) {
			await processUrl(bot, env, chatId, message.message_id, args);
			return;
		}

		// Otherwise, require a reply to a document
		const replyMsg = message.reply_to_message;
		if (!replyMsg?.document) {
			await bot.sendMessage(chatId, "⚠️ Please reply to a keybox.xml file with /keybox or provide a URL:\n<code>/keybox https://example.com/keybox.xml</code>", message.message_id);
			return;
		}
		await processDocument(bot, env, chatId, message.message_id, replyMsg.document.file_id, replyMsg.document.mime_type, replyMsg.document.file_size);
		return;
	}

	// Handle direct file upload (private chat only)
	if (message.document && message.chat.type === "private") {
		await processDocument(bot, env, chatId, message.message_id, message.document.file_id, message.document.mime_type, message.document.file_size);
		return;
	}
}

async function handleGuestMessage(bot: TelegramBot, message: TelegramMessage, env: Env): Promise<void> {
	const guestQueryId = message.guest_query_id;
	if (!guestQueryId) return;

	// Extract text - remove @bot_username mentions to get clean args
	const text = message.text || "";
	const cleanText = text.replace(/@\w+/g, "").trim();

	// Check if a URL is provided in the text
	const urlMatch = cleanText.match(/https?:\/\/\S+/i);
	if (urlMatch) {
		await processGuestUrl(bot, env, guestQueryId, urlMatch[0]);
		return;
	}

	// Check if replying to a message with a document
	const replyDoc = message.reply_to_message?.document;
	if (replyDoc) {
		await processGuestDocument(bot, env, guestQueryId, replyDoc.file_id, replyDoc.mime_type, replyDoc.file_size);
		return;
	}

	// No actionable content
	await bot.answerGuestQuery(
		guestQueryId,
		"⚠️ Please reply to a keybox.xml file and @mention me, or include a URL to a keybox.xml file.",
	);
}

async function processGuestDocument(
	bot: TelegramBot,
	env: Env,
	guestQueryId: string,
	fileId: string,
	mimeType?: string,
	fileSize?: number,
): Promise<void> {
	if (mimeType && mimeType !== "application/xml" && mimeType !== "text/xml") {
		await bot.answerGuestQuery(guestQueryId, "⚠️ Please send an XML file.");
		return;
	}

	if (fileSize && fileSize > 20 * 1024) {
		await bot.answerGuestQuery(guestQueryId, "⚠️ File too large. Maximum 20KB.");
		return;
	}

	try {
		const fileInfo = await bot.getFile(fileId);
		if (!fileInfo.file_path) {
			await bot.answerGuestQuery(guestQueryId, "❌ Failed to get file path.");
			return;
		}

		const fileBuffer = await bot.downloadFile(fileInfo.file_path);
		const xmlContent = new TextDecoder().decode(fileBuffer);

		const result = await checkKeybox(xmlContent);
		const reply = formatResult(result);
		await bot.answerGuestQuery(guestQueryId, reply);
	} catch (e) {
		const errMsg = e instanceof Error ? e.message : "Unknown error";
		await bot.answerGuestQuery(guestQueryId, `❌ Error: ${errMsg}`);
	}
}

async function processGuestUrl(
	bot: TelegramBot,
	env: Env,
	guestQueryId: string,
	url: string,
): Promise<void> {
	try {
		const res = await fetch(url, {
			headers: { "User-Agent": "KeyboxChecker/1.0" },
			redirect: "follow",
		});

		if (!res.ok) {
			await bot.answerGuestQuery(guestQueryId, `❌ Failed to fetch URL: HTTP ${res.status}`);
			return;
		}

		const contentLength = res.headers.get("content-length");
		if (contentLength && parseInt(contentLength, 10) > 20 * 1024) {
			await bot.answerGuestQuery(guestQueryId, "⚠️ Remote file too large. Maximum 20KB.");
			return;
		}

		const buffer = await res.arrayBuffer();
		if (buffer.byteLength > 20 * 1024) {
			await bot.answerGuestQuery(guestQueryId, "⚠️ Remote file too large. Maximum 20KB.");
			return;
		}

		let xmlContent = new TextDecoder().decode(buffer);
		if (!xmlContent.trimStart().startsWith("<")) {
			try {
				xmlContent = new TextDecoder().decode(
					Uint8Array.from(atob(xmlContent.trim()), (c) => c.charCodeAt(0)),
				);
			} catch {
				// Not valid base64, proceed with original content
			}
		}
		const result = await checkKeybox(xmlContent);
		const reply = formatResult(result);
		await bot.answerGuestQuery(guestQueryId, reply);
	} catch (e) {
		const errMsg = e instanceof Error ? e.message : "Unknown error";
		await bot.answerGuestQuery(guestQueryId, `❌ Error: ${errMsg}`);
	}
}

async function handleCallback(
	bot: TelegramBot,
	callbackQuery: NonNullable<TelegramUpdate["callback_query"]>,
	env: Env,
): Promise<void> {
	const data = callbackQuery.data;
	const msg = callbackQuery.message;
	if (!data || !msg) {
		await bot.answerCallbackQuery(callbackQuery.id);
		return;
	}

	const chatId = msg.chat.id;
	const messageId = msg.message_id;

	// Parse callback data: "cert:{kvKey}:{level}" or "overview:{kvKey}"
	const parts = data.split(":");
	if (parts.length < 2) {
		await bot.answerCallbackQuery(callbackQuery.id);
		return;
	}

	const action = parts[0];
	const kvKey = parts[1];

	// Retrieve stored result from KV
	const stored = await env.KV.get(kvKey, "json") as KeyboxResult | null;
	if (!stored) {
		await bot.answerCallbackQuery(callbackQuery.id, "⚠️ Result expired");
		return;
	}

	const keyboard = buildKeyboard(kvKey, stored.certInfos.length);

	if (action === "overview") {
		const text = formatResult(stored);
		await bot.editMessageText(chatId, messageId, text, keyboard);
	} else if (action === "cert") {
		const level = parseInt(parts[2], 10);
		if (isNaN(level) || level < 0 || level >= stored.certInfos.length) {
			await bot.answerCallbackQuery(callbackQuery.id, "Invalid level");
			return;
		}
		const text = formatCertDetail(stored.certInfos[level], stored.certInfos.length);
		await bot.editMessageText(chatId, messageId, text, keyboard);
	}

	await bot.answerCallbackQuery(callbackQuery.id);
}

function buildKeyboard(kvKey: string, certCount: number): InlineKeyboardButton[][] {
	const rows: InlineKeyboardButton[][] = [];

	// First row: Overview button
	rows.push([{ text: "📋 Overview", callback_data: `overview:${kvKey}` }]);

	// Cert level buttons - arrange in rows of up to 3
	const certButtons: InlineKeyboardButton[] = [];
	for (let i = 0; i < certCount; i++) {
		const label = i === 0 ? "🔏 Leaf" : i === certCount - 1 ? "🌳 Root" : `🔗 L${i}`;
		certButtons.push({ text: label, callback_data: `cert:${kvKey}:${i}` });
	}

	// Split into rows of 3
	for (let i = 0; i < certButtons.length; i += 3) {
		rows.push(certButtons.slice(i, i + 3));
	}

	return rows;
}

async function processDocument(
	bot: TelegramBot,
	env: Env,
	chatId: number,
	messageId: number,
	fileId: string,
	mimeType?: string,
	fileSize?: number,
): Promise<void> {
	if (mimeType && mimeType !== "application/xml" && mimeType !== "text/xml") {
		await bot.sendMessage(chatId, "⚠️ Please send an XML file.", messageId);
		return;
	}

	if (fileSize && fileSize > 20 * 1024) {
		await bot.sendMessage(chatId, "⚠️ File too large. Maximum 20KB.", messageId);
		return;
	}

	try {
		const fileInfo = await bot.getFile(fileId);
		if (!fileInfo.file_path) {
			await bot.sendMessage(chatId, "❌ Failed to get file path.", messageId);
			return;
		}

		const fileBuffer = await bot.downloadFile(fileInfo.file_path);
		const xmlContent = new TextDecoder().decode(fileBuffer);

		const result = await checkKeybox(xmlContent);

		// Store result in KV with 1-hour TTL
		const kvKey = crypto.randomUUID().slice(0, 8);
		await env.KV.put(kvKey, JSON.stringify(result), { expirationTtl: 3600 });

		const reply = formatResult(result);
		const keyboard = buildKeyboard(kvKey, result.certInfos.length);
		await bot.sendMessage(chatId, reply, messageId, keyboard);
	} catch (e) {
		const errMsg = e instanceof Error ? e.message : "Unknown error";
		await bot.sendMessage(chatId, `❌ Error: ${errMsg}`, messageId);
	}
}

async function processUrl(
	bot: TelegramBot,
	env: Env,
	chatId: number,
	messageId: number,
	url: string,
): Promise<void> {
	try {
		const res = await fetch(url, {
			headers: { "User-Agent": "KeyboxChecker/1.0" },
			redirect: "follow",
		});

		if (!res.ok) {
			await bot.sendMessage(chatId, `❌ Failed to fetch URL: HTTP ${res.status}`, messageId);
			return;
		}

		const contentLength = res.headers.get("content-length");
		if (contentLength && parseInt(contentLength, 10) > 20 * 1024) {
			await bot.sendMessage(chatId, "⚠️ Remote file too large. Maximum 20KB.", messageId);
			return;
		}

		const buffer = await res.arrayBuffer();
		if (buffer.byteLength > 20 * 1024) {
			await bot.sendMessage(chatId, "⚠️ Remote file too large. Maximum 20KB.", messageId);
			return;
		}

		let xmlContent = new TextDecoder().decode(buffer);
		if (!xmlContent.trimStart().startsWith("<")) {
			try {
				xmlContent = new TextDecoder().decode(
					Uint8Array.from(atob(xmlContent.trim()), (c) => c.charCodeAt(0)),
				);
			} catch {
				// Not valid base64, proceed with original content
			}
		}
		const result = await checkKeybox(xmlContent);

		const kvKey = crypto.randomUUID().slice(0, 8);
		await env.KV.put(kvKey, JSON.stringify(result), { expirationTtl: 3600 });

		const reply = formatResult(result);
		const keyboard = buildKeyboard(kvKey, result.certInfos.length);
		await bot.sendMessage(chatId, reply, messageId, keyboard);
	} catch (e) {
		const errMsg = e instanceof Error ? e.message : "Unknown error";
		await bot.sendMessage(chatId, `❌ Error: ${errMsg}`, messageId);
	}
}
