# -*- coding: utf-8 -*-
#
# Copyright 2013-2014
#    Lars Kiesow   <lkiesow@uos.de>
#    Sven Haardiek <sven@haardiek.de>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation
# are those of the authors and should not be interpreted as representing
# official policies, either expressed or implied, of everyone working on
# this project.
#
#
# == About ==================================================================
#
#  The weechat IRCrypt-Lite plug-in is a lite version of the IRCrypt plug-in.
#  It will send messages encrypted to all channels for which a passphrase is
#  set. A channel can either be a regular IRC multi-user channel (i.e.
#  #IRCrypt) or another users nickname.
#
# == Project ================================================================
#
# This plug-in is part of the IRCrypt project. For mor information or to
# participate, please visit
#
#   https://github.com/IRCrypt
#
#
# To report bugs, make suggestions, etc. for this particular plug-in, please
# have a look at:
#
#   https://github.com/IRCrypt/ircrypt-weechat
#


SCRIPT_NAME    = 'IRCrypt-Lite'
SCRIPT_AUTHOR  = 'Sven Haardiek <sven@haardiek.de>, Lars Kiesow <lkiesow@uos.de>'
SCRIPT_VERSION = 'SNAPSHOT'
SCRIPT_LICENSE = 'FreeBSD License'
SCRIPT_DESC    = 'IRCrypt-Lite: Encryption layer for IRC'

import weechat, string, os, subprocess, base64
import time


# Global buffers used to store message parts, pending requests, configuration
# options, keys, etc.
ircrypt_msg_buffer = {}
ircrypt_config_file = None
ircrypt_config_section = {}
ircrypt_config_option = {}
ircrypt_keys = {}
ircrypt_cipher = {}
ircrypt_gpg_binary = None

# Constants used throughout this script
MAX_PART_LEN     = 300
MSG_PART_TIMEOUT = 300 # 5min
NEVER            = 0
ALWAYS           = 1
IF_NEW           = 2


ircrypt_help_text = '''
Add, change or remove key for nick or channel.
Add, change or remove special cipher for nick or channel.

%(bold)sIRCryptLite command options: %(normal)s

list                                                 List set keys, ids and ciphers
set-key         [-server <server>] <target> <key>    Set key for target
remove-key      [-server <server>] <target>          Remove key for target
set-cipher      [-server <server>] <target> <cipher> Set specific cipher for channel
remove-cipher   [-server <server>] <target>          Remove specific cipher for channel


%(bold)sExamples: %(normal)s

Set the key for a channel:
  /ircrypt set-key -server freenet #IRCrypt key
Remove the key:
  /ircrypt remove-key #IRCrypt
Set the key for a user:
  /ircrypt set-key nick key
Switch to a specific cipher for a channel:
  /ircrypt set-cipher -server freenode #IRCrypt TWOFISH
Unset the specific cipher for a channel:
  /ircrypt remove-cipher #IRCrypt


%(bold)sConfiguration: %(normal)s

Tip: You can list all options and what they are currently set to by executing:
   /set ircrypt.*

%(bold)sircrypt.marker.encrypted %(normal)s
   This option will set a string which is displayed in encrypted channels,
   indicating that the current channel is encrypted. If “{{cipher}}” is used as
   part of this string, it will be replaced by the cipher currently used by
   oneself for that particular channel.
%(bold)sircrypt.marker.unencrypted %(normal)s
   This option will set a string which is displayed before each message that is
   send unencrypted in a channel for which a key is set. So you know when
   someone is talking to you without encryption.
%(bold)sircrypt.cipher.sym_cipher %(normal)s
   This will set the default cipher used for symmetric encryption. You can get
   a list of available ciphers by running “gpg --version”.

Additional to these direct configuration options you can add 'ircrypt' to
weechat.bar.status.items to have an indication that the message you are going
to send is encrypted. The message displayed id the one set with the
configuration option ircrypt.marker.encrypted.

It is woth noting that you probably don't want to replace the whole value of
that option but extend it instead in a way like:
   /set weechat.bar.status.items {{currentContent}},ircrypt
''' % {'bold':weechat.color('bold'), 'normal':weechat.color('-bold')}


class MessageParts:
	'''Class used for storing parts of messages which were split after
	encryption due to their length.'''

	modified = 0
	last_id  = None
	message  = ''

	def update(self, id, msg):
		'''This method updates an already existing message part by adding a new
		part to the old ones and updating the identifier of the latest received
		message part.
		'''
		# Check if id is correct. If not, throw away old parts:
		if self.last_id and self.last_id != id+1:
			self.message = ''
		# Check if the are old message parts which belong due to their old age
		# probably not to this message:
		if time.time() - self.modified > MSG_PART_TIMEOUT:
			self.message = ''
		self.last_id = id
		self.message = msg + self.message
		self.modified = time.time()

def decrypt(data, msgtype, servername, args):
	'''Hook for incomming PRVMSG commands.
	This method will parse the input, check if it is an encrypted message and if
	it is, call the functions decrypt_sym or decrypt_asym to decrypt it.

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	'''
	global ircrypt_config_option, ircrypt_keys

	info = weechat.info_get_hashtable('irc_message_parse', { 'message': args })

	# Check if asymmetric encrypted and if asymetric encryption is enabled
	if '>ACRY' in args:
		if '>ACRY-0' in args:
			weechat.command('','/notice %s >UCRY-NOASYM' % info['nick'])
		return ''

	# Check if channel is own nick and if change channel to nick of sender
	if info['channel'][0] not in '#&':
		info['channel'] = info['nick']

	# Get key
	key = ircrypt_keys.get('%s/%s' % (servername, info['channel']))
	if key:
		# if key exists and >CRY part of message start symmetric encryption
		if '>CRY-' in args:
			return decrypt_sym(servername, args, info, key)
		# if key exisits and no >CRY not part of message flag message as unencrypted
		else:
			pre, message = string.split(args, ' :', 1)
			return '%s :%s %s' % (pre,
					weechat.config_string(ircrypt_config_option['unencrypted']),
					message)

	# If no asymmetric or symmetric encryption return arguments
	return args


def decrypt_sym(servername, args, info, key):
	'''This method is called to decrypt an symmetric encrypted messages and put
	them together again if necessary.

	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	:param info: dictionary created by info_get_hashtable
	:param key: key for decryption
	'''
	global ircrypt_msg_buffer, ircrypt_config_option

	pre, message    = string.split(args, '>CRY-', 1)
	number, message = string.split(message, ' ', 1 )

	# Get key for the message buffer
	buf_key = '%s.%s.%s' % (servername, info['channel'], info['nick'])

	# Decrypt only if we got last part of the message
	# otherwise put the message into a globa buffer and quit
	if int(number) != 0:
		if not buf_key in ircrypt_msg_buffer:
			ircrypt_msg_buffer[buf_key] = MessageParts()
		ircrypt_msg_buffer[buf_key].update(int(number), message)
		return ''

	# Get whole message
	try:
		message = message + ircrypt_msg_buffer[buf_key].message
	except KeyError:
		pass

	# Decrypt
	p = subprocess.Popen([ircrypt_gpg_binary, '--batch',  '--no-tty', '--quiet',
		'--passphrase-fd', '-', '-d'],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	p.stdin.write('%s\n' % key)
	p.stdin.write(base64.b64decode(message))
	p.stdin.close()
	decrypted = p.stdout.read()
	p.stdout.close()

	# Get and print GPG errors/warnings
	err = p.stderr.read()
	p.stderr.close()
	if err:
		buf = weechat.buffer_search('irc', '%s.%s' % (servername,info['channel']))
		weechat.prnt(buf, 'GPG reported error:\n%s' % err)

	# Remove old messages from buffer
	try:
		del ircrypt_msg_buffer[buf_key]
	except KeyError:
		pass
	return '%s%s' % (pre, decrypted)


def encrypt(data, msgtype, servername, args):
	'''Hook for outgoing PRVMSG commands.
	This method will call the functions encrypt_sym and encrypt_asym to encrypt
	outgoing messages symmetric or asymmetric

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	'''
	global ircrypt_keys
	info = weechat.info_get_hashtable("irc_message_parse", { "message": args })

	# check symmetric key
	key = ircrypt_keys.get('%s/%s' % (servername, info['channel']))
	if key:
		return encrypt_sym(servername, args, info, key)

	# No key -> don't encrypt
	return args


def encrypt_sym(servername, args, info, key):
	'''This method will symmetric encrypt messages and if necessary (if
	they grow to large) split them into multiple parts.

	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	:param info: dictionary created by info_get_hashtable
	:param key: key for decryption
	'''

	global ircrypt_cipher

	# Get cipher
	cipher = ircrypt_cipher.get('%s/%s' % (servername, info['channel']),
			weechat.config_string(ircrypt_config_option['sym_cipher']))
	# Get prefix and message
	pre, message = string.split(args, ':', 1)

	# encrypt message
	p = subprocess.Popen([ircrypt_gpg_binary, '--batch',  '--no-tty', '--quiet',
		'--symmetric', '--cipher-algo',
		cipher,
		'--passphrase-fd', '-'],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	p.stdin.write('%s\n' % key)
	p.stdin.write(message)
	p.stdin.close()
	encrypted = base64.b64encode(p.stdout.read())
	p.stdout.close()

	# Get and print GPG errors/warnings
	err = p.stderr.read()
	p.stderr.close()
	if err:
		buf = weechat.buffer_search('irc', '%s.%s' % (servername, info['channel']))
		weechat.prnt(buf, 'GPG reported error:\n%s' % err)

	#create output
	output = '%s:>CRY-0 %s' % (pre, encrypted)
	# Check if encrypted message is to long.
	# If that is the case, send multiple messages.
	if len(output) > MAX_PART_LEN:
		output = '%s:>CRY-1 %s\r\n%s' % (pre, output[MAX_PART_LEN:],
				output[:MAX_PART_LEN])
	return output


def ircrypt_config_init():
	''' This method initializes the configuration file. It creates sections and
	options in memory and prepares the handling of key sections.
	'''
	global ircrypt_config_file, ircrypt_config_section, ircrypt_config_option
	ircrypt_config_file = weechat.config_new('ircrypt-lite', 'ircrypt_config_reload_cb', '')
	if not ircrypt_config_file:
		return

	# marker
	ircrypt_config_section['marker'] = weechat.config_new_section(
			ircrypt_config_file, 'marker', 0, 0, '', '', '', '', '', '', '', '',
			'', '')
	if not ircrypt_config_section['marker']:
		weechat.config_free(ircrypt_config_file)
		return
	ircrypt_config_option['encrypted'] = weechat.config_new_option(
			ircrypt_config_file, ircrypt_config_section['marker'],
			'encrypted', 'string', 'Marker for encrypted messages', '', 0, 0,
			'encrypted', 'encrypted', 0, '', '', '', '', '', '')
	ircrypt_config_option['unencrypted'] = weechat.config_new_option(
			ircrypt_config_file, ircrypt_config_section['marker'], 'unencrypted',
			'string', 'Marker for unencrypted messages received in an encrypted channel',
			'', 0, 0, '', 'u', 0, '', '', '', '', '', '')

	# cipher options
	ircrypt_config_section['cipher'] = weechat.config_new_section(
			ircrypt_config_file, 'cipher', 0, 0, '', '', '', '', '', '', '', '',
			'', '')
	if not ircrypt_config_section['cipher']:
		weechat.config_free(ircrypt_config_file)
		return
	ircrypt_config_option['sym_cipher'] = weechat.config_new_option(
			ircrypt_config_file, ircrypt_config_section['cipher'],
			'sym_cipher', 'string', 'symmetric cipher used by default', '', 0, 0,
			'TWOFISH', 'TWOFISH', 0, '', '', '', '', '', '')

	# general options
	ircrypt_config_section['general'] = weechat.config_new_section(
			ircrypt_config_file, 'general', 0, 0, '', '', '', '', '', '', '', '',
			'', '')
	if not ircrypt_config_section['general']:
		weechat.config_free(ircrypt_config_file)
		return
	ircrypt_config_option['binary'] = weechat.config_new_option(
			ircrypt_config_file, ircrypt_config_section['general'],
			'binary', 'string', 'GnuPG binary to use', '', 0, 0,
			'', '', 0, '', '', '', '', '', '')

	# keys
	ircrypt_config_section['keys'] = weechat.config_new_section(
			ircrypt_config_file, 'keys', 0, 0, 'ircrypt_config_keys_read_cb', '',
			'ircrypt_config_keys_write_cb', '', '', '', '', '', '', '')
	if not ircrypt_config_section['keys']:
		weechat.config_free(ircrypt_config_file)

	# Special Ciphers
	ircrypt_config_section['special_cipher'] = weechat.config_new_section(
			ircrypt_config_file, 'special_cipher', 0, 0,
			'ircrypt_config_special_cipher_read_cb', '',
			'ircrypt_config_special_cipher_write_cb', '', '', '', '', '', '', '')
	if not ircrypt_config_section['special_cipher']:
		weechat.config_free(ircrypt_config_file)


def ircrypt_config_reload_cb(data, config_file):
	'''Handle a reload of the configuration file.
	'''
	return weechat.WEECHAT_CONFIG_READ_OK


def ircrypt_config_read():
	''' Read IRCrypt configuration file (ircrypt.conf).
	'''
	global ircrypt_config_file
	return weechat.config_read(ircrypt_config_file)


def ircrypt_config_write():
	''' Write IRCrypt configuration file (ircrypt.conf) to disk.
	'''
	global ircrypt_config_file
	return weechat.config_write(ircrypt_config_file)


def ircrypt_config_keys_read_cb(data, config_file, section_name, option_name,
		value):
	'''Read elements of the key section from the configuration file.
	'''
	global ircrypt_keys

	if not weechat.config_new_option(config_file, section_name, option_name,
			'string', 'key', '', 0, 0, '', value, 0, '', '', '', '', '', ''):
		return weechat.WEECHAT_CONFIG_OPTION_SET_ERROR

	ircrypt_keys[option_name] = value
	return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED


def ircrypt_config_keys_write_cb(data, config_file, section_name):
	'''Write passphrases to the key section of the configuration file.
	'''
	global ircrypt_keys

	weechat.config_write_line(config_file, section_name, '')
	for target, key in sorted(ircrypt_keys.iteritems()):
		weechat.config_write_line(config_file, target, key)

	return weechat.WEECHAT_RC_OK


def ircrypt_config_special_cipher_read_cb(data, config_file, section_name,
		option_name, value):
	'''Read elements of the key section from the configuration file.
	'''
	global ircrypt_cipher

	if not weechat.config_new_option(config_file, section_name, option_name,
			'string', 'special_cipher', '', 0, 0, '', value, 0, '', '', '', '',
			'', ''):
		return weechat.WEECHAT_CONFIG_OPTION_SET_ERROR

	ircrypt_cipher[option_name] = value
	return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED


def ircrypt_config_special_cipher_write_cb(data, config_file, section_name):
	'''Write passphrases to the key section of the configuration file.
	'''
	global ircrypt_cipher

	weechat.config_write_line(config_file, section_name, '')
	for target, cipher in sorted(ircrypt_cipher.iteritems()):
		weechat.config_write_line(config_file, target, cipher)

	return weechat.WEECHAT_RC_OK


def ircrypt_command_list():
	'''ircrypt command to list the keys, asymmetric identifier and Special Cipher'''

	global ircrypt_keys, ircrypt_cipher

	# Get buffer
	buffer = weechat.current_buffer()
	# Print keys and special cipher in current buffer
	weechat.prnt(buffer,'\nKeys:')
	for servchan,key in ircrypt_keys.iteritems():
		weechat.prnt(buffer,'%s : %s' % (servchan, key))

	weechat.prnt(buffer,'\nSpecial Cipher:')
	for servchan,spcip in ircrypt_cipher.iteritems():
		weechat.prnt(buffer,'%s : %s' % (servchan, spcip))

	weechat.prnt(buffer,'\n')
	return weechat.WEECHAT_RC_OK


def ircrypt_command_set_keys(target, key):
	'''ircrypt command to set key for target (target is a server/channel combination)'''
	global ircrypt_keys
	# Set key
	ircrypt_keys[target] = key
	# Print status message to current buffer
	weechat.prnt(weechat.current_buffer(),'Set key for %s' % target)
	return weechat.WEECHAT_RC_OK


def ircrypt_command_remove_keys(target):
	'''ircrypt command to remove key for target (target is a server/channel combination)'''
	global ircrypt_keys
	# Get buffer
	buffer = weechat.current_buffer()
	# Check if key is set and print error in current buffer otherwise
	if target not in ircrypt_keys:
		weechat.prnt(buffer, 'No existing key for %s.' % target)
		return weechat.WEECHAT_RC_OK
	# Delete key and print status message in current buffer
	del ircrypt_keys[target]
	weechat.prnt(buffer, 'Removed key for %s' % target)
	return weechat.WEECHAT_RC_OK


def ircrypt_command_set_cip(target, cipher):
	'''ircrypt command to set key for target (target is a server/channel combination)'''
	global ircrypt_cipher
	# Set special cipher
	ircrypt_cipher[target] = cipher
	# Print status message in current buffer
	weechat.prnt(weechat.current_buffer(),'Set cipher %s for %s' % (cipher, target))
	return weechat.WEECHAT_RC_OK

def ircrypt_command_remove_cip(target):
	'''ircrypt command to remove key for target (target is a server/channel combination)'''
	global ircrypt_cipher
	# Get buffer
	buffer = weechat.current_buffer()
	# Check if special cipher is set and print error in current buffer otherwise
	if target not in ircrypt_cipher:
		weechat.prnt(buffer, 'No special cipher set for %s.' % target)
		return weechat.WEECHAT_RC_OK
	# Delete special cipher and print status message in current buffer
	del ircrypt_cipher[target]
	weechat.prnt(buffer, 'Removed special cipher. Use default cipher for %s instead.' % target)
	return weechat.WEECHAT_RC_OK

def ircrypt_command(data, buffer, args):
	'''Hook to handle the /ircrypt weechat command. This method is also used for
	all commands typed into the IRCrypt buffer.
	'''
	global ircrypt_keys, ircrypt_cipher

	argv = [a for a in args.split(' ') if a]

	if argv and not argv[0] in ['list', 'buffer', 'set-key', 'remove-key',
			'set-cipher', 'remove-cipher']:
		weechat.prnt(buffer, '%sUnknown command. Try  /help ircrypt' % \
				weechat.prefix('error'))
		return weechat.WEECHAT_RC_OK

	# list
	if not argv or argv == ['list']:
		return ircrypt_command_list()

	# Check if a server was set
	if (len(argv) > 2 and argv[1] == '-server'):
		server_name = argv[2]
		del argv[2]
		del argv[1]
		args = args.split(' ', 2)[-1]
	else:
		# Try to determine the server automatically
		server_name = weechat.buffer_get_string(buffer, 'localvar_server')

	# All remaining commands need a server name
	if not server_name:
		# if no server was set print message in ircrypt buffer and throw error
		weechat.prnt(buffer, 'Unknown Server. Please use -server to specify server')
		return weechat.WEECHAT_RC_ERROR

	# For the remaining commands we need at least one additional argument
	if len(argv) < 2:
		return weechat.WEECHAT_RC_ERROR

	target = '%s/%s' % (server_name, argv[1])

	# Set keys
	if argv[0] == 'set-key':
		if len(argv) < 3:
			return weechat.WEECHAT_RC_ERROR
		return ircrypt_command_set_keys(target, ' '.join(argv[2:]))

	# Remove keys
	if argv[0] == 'remove-key':
		if len(argv) != 2:
			return weechat.WEECHAT_RC_ERROR
		return ircrypt_command_remove_keys(target)

	# Set special cipher for channel
	if argv[0] == 'set-cipher':
		if len(argv) < 3:
			return weechat.WEECHAT_RC_ERROR
		return ircrypt_command_set_cip(target, ' '.join(argv[2:]))

	# Remove secial cipher for channel
	if argv[0] == 'remove-cipher':
		if len(argv) != 2:
			return weechat.WEECHAT_RC_ERROR
		return ircrypt_command_remove_cip(target)

	# Error if command was unknown
	return weechat.WEECHAT_RC_ERROR


def ircrypt_encryption_statusbar(*args):
	'''This method will set the “ircrypt” element of the status bar if
	encryption is enabled for the current channel. The placeholder {{cipher}}
	can be used, which will be replaced with the cipher used for the current
	channel.
	'''
	global ircrypt_cipher

	channel = weechat.buffer_get_string(weechat.current_buffer(), 'localvar_channel')
	server  = weechat.buffer_get_string(weechat.current_buffer(), 'localvar_server')
	key = ircrypt_keys.get('%s/%s' % (server, channel))

	# Return nothing if no key is set for current channel
	if not key:
		return ''

	# Return marer, but replace {{cipher}} with used cipher for current channel
	return weechat.config_string(ircrypt_config_option['encrypted']).replace(
			'{{cipher}}', ircrypt_cipher.get('%s/%s' % (server, channel),
				weechat.config_string(ircrypt_config_option['sym_cipher'])))


def ircrypt_notice_hook(data, msgtype, servername, args):

	info = weechat.info_get_hashtable('irc_message_parse', { 'message': args })

	# Check for error messages
	if '>UCRY-' in args:
		# TODO: Add error handler
		return args

	# Incomming key request.
	if '>WCRY-' in args:
		if '>WCRY-0' in args:
			weechat.command('','/notice %s >UCRY-NOEXCHANGE' % info['nick'])
		return ''

	return args


def ircrypt_find_gpg_binary():
	'''Check for GnuPG binary to use
	:returns: Tuple with binary name and version.
	'''
	for binary in ('gpg2','gpg'):
		try:
			p = subprocess.Popen([binary, '--version'],
					stdout=subprocess.PIPE,
					stderr=subprocess.PIPE)
			version = p.stdout.read().split('\n',1)[0]
			if p.wait():
				continue
			return binary, version
		except:
			pass
	return None, None


def ircrypt_check_binary():
	'''If binary is not set, try to determine it automatically
	'''
	global ircrypt_gpg_binary
	ircrypt_gpg_binary = weechat.config_string(ircrypt_config_option['binary'])
	if ircrypt_gpg_binary:
		return
	ircrypt_gpg_binary,version = ircrypt_find_gpg_binary()
	if not ircrypt_gpg_binary:
		weechat.prnt('', '%sAutomatic detection of the GnuPG binary failed and '
				'nothing is set manually. You wont be able to use IRCrypt like '
				'this. Please install GnuPG or set the path to the binary to '
				'use.' % weechat.prefix('error'))
	else:
		weechat.prnt('', 'Found %s' % version)
		weechat.config_option_set(ircrypt_config_option['binary'], ircrypt_gpg_binary, 1)


# register plugin
if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
		SCRIPT_DESC, 'ircrypt_unload_script', 'UTF-8'):
	# register the modifiers
	weechat.hook_modifier('irc_in_privmsg',  'decrypt', '')
	weechat.hook_modifier('irc_out_privmsg', 'encrypt', '')
	weechat.hook_modifier('irc_in_notice',   'ircrypt_notice_hook', '')

	weechat.hook_command('ircrypt', 'Manage IRCrypt-Lite Keys',
			'[list] '
			'| set-key [-server <server>] <target> <key> '
			'| remove-key [-server <server>] <target> '
			'| set-cipher [-server <server>] <target> <cipher> '
			'| remove-cipher [-server <server>] <target> ',
			ircrypt_help_text,
			'list || set-key %(irc_channel)|%(nicks)|-server %(irc_servers) %- '
			'|| remove-key %(irc_channel)|%(nicks)|-server %(irc_servers) %- '
			'|| set-cipher %(irc_channel)|-server %(irc_servers) %- '
			'|| remove-cipher |%(irc_channel)|-server %(irc_servers) %-',
			'ircrypt_command', '')

	ircrypt_config_init()
	ircrypt_config_read()
	ircrypt_check_binary()
	weechat.bar_item_new('ircrypt', 'ircrypt_encryption_statusbar', '')
	weechat.hook_signal('ircrypt_buffer_opened', 'update_encryption_status', '')


def ircrypt_unload_script():
	'''Hook to ensure the configuration is properly written to disk when the
	script is unloaded.
	'''
	ircrypt_config_write()
	return weechat.WEECHAT_RC_OK
