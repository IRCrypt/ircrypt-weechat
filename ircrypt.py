# DON'T USE THIS SCRIPT IN THE CURRENT STATE!

SCRIPT_NAME    = 'IRCrypt'
SCRIPT_AUTHOR  = 'Sven Haardiek <sven@haardiek.de>, Lars Kiesow <lkiesow@uos.de>'
SCRIPT_VERSION = '0.0.0'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC    = 'IRCrypt - blabla'

import weechat, string, os, subprocess, base64


ircrypt_msg_buffer = {}


def decrypt(data, msgtype, servername, args):
	global ircrypt_msg_buffer

	dict = weechat.info_get_hashtable("irc_message_parse", { "message": args })
	# ircrypt_msg_buffer[dict['nick']] = ['msg-part-2', 'msg-part-1']
	weechat.prnt("", "dict: %s" % dict)
	weechat.prnt("", args)
	if (dict['channel'] != '#IRCrypt'):
		return args
	prepre, pre, message = string.split(args, ':', 2)
	return '%s:%s:%s' % (prepre, pre, '')


def encrypt(data, msgtype, servername, args):
	dict = weechat.info_get_hashtable("irc_message_parse", { "message": args })
	weechat.prnt("", "dict: %s" % dict)
	if (dict['channel'] != '#IRCrypt'):
		return args
	pre, message = string.split(args, ':', 1)
	p = subprocess.Popen(['gpg', '--batch',  '--no-tty', '--quiet', 
		'--symmetric', '--cipher-algo', 'TWOFISH', '--passphrase-fd', '-'], 
		stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	p.stdin.write('passwort1\n')
	p.stdin.write(message)
	p.stdin.close()
	encrypted = base64.b64encode(p.stdout.read())
	p.stdout.close()

	output = '%s:>CRY-0 %s' % (pre, encrypted)
	# Check if encrypted message is to long.
	# If that is the case, send multiple messages.
	weechat.prnt('', '%i' % len(args) )
	weechat.prnt('', '%i' % len(output) )
	weechat.prnt('', '%s' % output )
	if len(output) > 400:
		output = '%s:>CRY-1 %s\r\n%s' % (pre, output[400:], output[:400])
	return output


# register plugin
if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, '', 'UTF-8'):
	# register the modifiers
	weechat.hook_modifier('irc_in_privmsg', 'decrypt', '')
	weechat.hook_modifier('irc_out_privmsg', 'encrypt', '')
