# DON'T USE THIS SCRIPT IN THE CURRENT STATE!

SCRIPT_NAME    = 'IRCrypt'
SCRIPT_AUTHOR  = 'Sven Haardiek <sven@haardiek.de>, Lars Kiesow <lkiesow@uos.de>'
SCRIPT_VERSION = '0.0.0'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC    = 'IRCrypt - blabla'

import weechat, string, os, subprocess, base64, curses


ircrypt_msg_buffer = {}


def decrypt(data, msgtype, servername, args):
	'''Hook for incomming PRVMSG commands.
	This method will parse the input, check if it is an encrypted message and if
	it is, decrypt it.

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	'''
	global ircrypt_msg_buffer

	dict = weechat.info_get_hashtable("irc_message_parse", { "message": args })
	if (dict['channel'] != '#IRCrypt'):
		return args
	pre, message    = string.split(args, '>CRY-', 1)
	number, message = string.split(message, ' ', 1 )

	if not dict['nick'] in ircrypt_msg_buffer:
		ircrypt_msg_buffer[dict['nick']] = []
	
	ircrypt_msg_buffer[dict['nick']].insert(0,message)

	# Encrypt only if we got last part of the message
	if int(number) != 0:
		return ''

	# Combine message parts
	message = ''.join(ircrypt_msg_buffer[dict['nick']])

	p = subprocess.Popen(['gpg', '--batch',  '--no-tty', '--quiet', 
		'--passphrase-fd', '-', '-d'], 
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	p.stdin.write('passwort1\n')
	p.stdin.write(base64.b64decode(message))
	p.stdin.close()
	decrypted = p.stdout.read()
	p.stdout.close()

	# Get and print GPG errors/warnings
	err = p.stderr.read()
	p.stderr.close()
	if err:
		buf = weechat.buffer_search('irc', '%s.#IRCrypt' % servername)
		weechat.prnt(buf, 'GPG reported error:\n%s' % err)

	# Remove old messages from buffer
	del ircrypt_msg_buffer[dict['nick']]
	return '%s%s' % (pre, decrypted)



def encrypt(data, msgtype, servername, args):
	'''Hook for outgoing PRVMSG commands.
	This method will encrypt outgoing messages and if necessary (if they grow to
	large) split them into multiple parts.

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	'''
	dict = weechat.info_get_hashtable("irc_message_parse", { "message": args })
	# weechat.prnt("", "dict: %s" % dict)
	if (dict['channel'] != '#IRCrypt'):
		return args
	pre, message = string.split(args, ':', 1)
	p = subprocess.Popen(['gpg', '--batch',  '--no-tty', '--quiet', 
		'--symmetric', '--cipher-algo', 'TWOFISH', '--passphrase-fd', '-'], 
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	p.stdin.write('passwort1\n')
	p.stdin.write(message)
	p.stdin.close()
	encrypted = base64.b64encode(p.stdout.read())
	p.stdout.close()
	# Get and print GPG errors/warnings
	err = p.stderr.read()
	p.stderr.close()
	if err:
		buf = weechat.buffer_search('irc', '%s.#IRCrypt' % servername)
		weechat.prnt(buf, 'GPG reported error:\n%s' % err)

	output = '%s:>CRY-0 %s' % (pre, encrypted)
	# Check if encrypted message is to long.
	# If that is the case, send multiple messages.
	if len(output) > 400:
		output = '%s:>CRY-1 %s\r\n%s' % (pre, output[400:], output[:400])
	return output


def ask_passwd():
	'''This method uses curses to open a window and ask for a password which is
	not printed onto the screen while it is typed in.
	'''
	# Initialize the curses module
	screen = curses.initscr()

	# Create the password window
	h,w = screen.getmaxyx()
	s = curses.newwin(5,21,h/2-2,w/2-10)
	s.box()

	# Neither do we want to see what we are typing nor do we need a cursor
	curses.noecho()
	curses.curs_set(0)
	s.addstr(2,2,"Enter password...")
	s.refresh()

	passwd = s.getstr(2,18,150)

	# Reset settings
	curses.echo()
	curses.curs_set(1)

	return passwd


def ircrypt_command(data, buffer, args):
	'''Hook to handle the /ircrypt weechat command.
	'''
	weechat.prnt(buffer, 'Password: %s' % ask_passwd())
	return weechat.WEECHAT_RC_OK


# register plugin
if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, '', 'UTF-8'):
	# register the modifiers
	weechat.hook_modifier('irc_in_privmsg', 'decrypt', '')
	weechat.hook_modifier('irc_out_privmsg', 'encrypt', '')

	weechat.hook_command('ircrypt', 'Manage IRCrypt Keys',
			'shorthelp...', 'longhelp...', '', 'ircrypt_command', '')
