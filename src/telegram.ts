export interface TelegramUpdate {
	update_id: number;
	message?: TelegramMessage;
	callback_query?: TelegramCallbackQuery;
	guest_message?: TelegramMessage;
}

export interface TelegramMessage {
	message_id: number;
	chat: { id: number; type: string };
	from?: { id: number };
	text?: string;
	document?: TelegramDocument;
	reply_to_message?: TelegramMessage;
	guest_query_id?: string;
}

export interface TelegramDocument {
	file_id: string;
	file_name?: string;
	mime_type?: string;
	file_size?: number;
}

export interface TelegramCallbackQuery {
	id: string;
	from: { id: number };
	message?: { message_id: number; chat: { id: number } };
	data?: string;
}

interface TelegramFile {
	file_id: string;
	file_path?: string;
}

export interface InlineKeyboardButton {
	text: string;
	callback_data: string;
}

interface InlineQueryResultArticle {
	type: "article";
	id: string;
	title: string;
	input_message_content: {
		message_text: string;
		parse_mode?: string;
	};
}

export class TelegramBot {
	private readonly apiBase: string;

	constructor(private readonly token: string) {
		this.apiBase = `https://api.telegram.org/bot${token}`;
	}

	async getFile(fileId: string): Promise<TelegramFile> {
		const res = await fetch(`${this.apiBase}/getFile`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ file_id: fileId }),
		});
		const data = (await res.json()) as { ok: boolean; result: TelegramFile };
		if (!data.ok) throw new Error("Failed to get file info");
		return data.result;
	}

	async downloadFile(filePath: string): Promise<ArrayBuffer> {
		const url = `https://api.telegram.org/file/bot${this.token}/${filePath}`;
		const res = await fetch(url);
		if (!res.ok) throw new Error("Failed to download file");
		return res.arrayBuffer();
	}

	async sendMessage(
		chatId: number,
		text: string,
		replyToMessageId?: number,
		inlineKeyboard?: InlineKeyboardButton[][],
	): Promise<void> {
		await fetch(`${this.apiBase}/sendMessage`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				chat_id: chatId,
				text,
				parse_mode: "HTML",
				...(replyToMessageId && { reply_parameters: { message_id: replyToMessageId } }),
				...(inlineKeyboard && { reply_markup: { inline_keyboard: inlineKeyboard } }),
			}),
		});
	}

	async editMessageText(
		chatId: number,
		messageId: number,
		text: string,
		inlineKeyboard?: InlineKeyboardButton[][],
	): Promise<void> {
		await fetch(`${this.apiBase}/editMessageText`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				chat_id: chatId,
				message_id: messageId,
				text,
				parse_mode: "HTML",
				...(inlineKeyboard && { reply_markup: { inline_keyboard: inlineKeyboard } }),
			}),
		});
	}

	async answerCallbackQuery(callbackQueryId: string, text?: string): Promise<void> {
		await fetch(`${this.apiBase}/answerCallbackQuery`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				callback_query_id: callbackQueryId,
				...(text && { text }),
			}),
		});
	}

	async answerGuestQuery(guestQueryId: string, text: string, parseMode = "HTML"): Promise<void> {
		const result: InlineQueryResultArticle = {
			type: "article",
			id: crypto.randomUUID(),
			title: "Keybox Check Result",
			input_message_content: {
				message_text: text,
				parse_mode: parseMode,
			},
		};
		await fetch(`${this.apiBase}/answerGuestQuery`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				guest_query_id: guestQueryId,
				result,
			}),
		});
	}

	async setWebhook(url: string): Promise<boolean> {
		const res = await fetch(`${this.apiBase}/setWebhook`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ url, allowed_updates: ["message", "callback_query", "guest_message"] }),
		});
		const data = (await res.json()) as { ok: boolean };
		return data.ok;
	}
}
