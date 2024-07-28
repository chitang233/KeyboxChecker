import subprocess
import tempfile
import re
import requests
import telebot
from os import getenv


def extract_serial_number(cert_pem):
	with tempfile.NamedTemporaryFile(delete=True) as temp_cert_file:
		temp_cert_file.write(cert_pem.encode())
		temp_cert_file.flush()
		result = subprocess.run(
			['openssl', 'x509', '-text', '-noout', '-in', temp_cert_file.name],
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True
		)
		if result.returncode != 0:
			raise RuntimeError(f"OpenSSL error: {result.stderr}")
		cert_text = result.stdout
	pattern = r"Serial Number:\n\s*([\da-f:]+)"
	match = re.search(pattern, cert_text, re.IGNORECASE)
	if match:
		serial_number = match.group(1).replace(":", "")
		hex_serial_number = hex(int(serial_number, 16)).split("0x")[1]
		return hex_serial_number.lower()
	else:
		return None


def get_google_sn_list():
	url = "https://android.googleapis.com/attestation/status"
	response = requests.get(
		url,
		headers={
			"Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
			"Pragma": "no-cache",
			"Expires": "0",
		}
	).json()
	return response


API_TOKEN = getenv('API_TOKEN')
bot = telebot.TeleBot(API_TOKEN)


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
	bot.reply_to(message, "Send me keybox.xml and I will check if it's revoked")


@bot.message_handler(content_types=['document'])
def handle_docs_audio(message):
	file_info = bot.get_file(message.document.file_id)
	file = requests.get('https://api.telegram.org/file/bot{0}/{1}'.format(API_TOKEN, file_info.file_path))
	certificate = file.text
	certificate = certificate.split("<Certificate format=\"pem\">")[1]
	certificate = certificate.split("</Certificate>")[0]
	serial_number = extract_serial_number(certificate)
	reply = f"Serial number: `{serial_number}`"
	try:
		status = get_google_sn_list()['entries'][serial_number]
		reply += f"\nSerial number found in Google's revoked keybox list\nReason: `{status['reason']}`"
	except KeyError:
		reply += "\nSerial number not found in Google's revoked keybox list"
	bot.reply_to(message, reply, parse_mode='Markdown')


bot.infinity_polling()
