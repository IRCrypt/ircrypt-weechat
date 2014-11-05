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
#  The weechat IRCrypt plug-in will send messages encrypted to all channels for
#  which a passphrase is set. A channel can either be a regular IRC multi-user
#  channel (i.e. #IRCrypt) or another users nickname.
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


SCRIPT_NAME    = 'IRCrypt'
SCRIPT_AUTHOR  = 'Sven Haardiek <sven@haardiek.de>, Lars Kiesow <lkiesow@uos.de>'
SCRIPT_VERSION = 'SNAPSHOT'
SCRIPT_LICENSE = 'FreeBSD License'
SCRIPT_DESC    = 'IRCrypt: Encryption layer for IRC'

import weechat, string, os, subprocess, base64, time


# Global buffers used to store message parts, pending requests, configuration
# options, keys, etc.
ircrypt_msg_buffer       = {}
ircrypt_config_file      = None
ircrypt_config_section   = {}
ircrypt_config_option    = {}
ircrypt_keys             = {}
ircrypt_asym_id          = {}
ircrypt_cipher           = {}
ircrypt_buffer           = None
ircrypt_pending_requests = []
ircrypt_request_buffer   = {}
ircrypt_pending_keys     = []
ircrypt_keys_buffer      = {}
ircrypt_gpg_binary       = None
ircrypt_message_plain    = {}
ircrypt_gpg_homedir      = None
ircrypt_gpg_id           = None

# Constants used throughout this script
MAX_PART_LEN     = 300
MSG_PART_TIMEOUT = 300 # 5min
NEVER            = 0
ALWAYS           = 1
IF_NEW           = 2


ircrypt_help_text = '''
Add, change or remove key for nick or channel.
Add, change or remove public key identifier for nick.
Add, change or remove special cipher for nick or channel.

%(bold)sIRCrypt command options: %(normal)s

list                                                 List set keys, ids and ciphers
buffer                                               Switch to/Open IRCrypt buffer
set-key         [-server <server>] <target> <key>    Set key for target
remove-key      [-server <server>] <target>          Remove key for target
set-gpg-id      [-server <server>] <nick> <id>       Set public key identifier for nick
remove-gpg-id   [-server <server>] <nick>            Remove public key identifier for nick
set-cipher      [-server <server>] <target> <cipher> Set specific cipher for channel
remove-cipher   [-server <server>] <target>          Remove specific cipher for channel
exchange        [-server <server>] <nick> [<target>] Request key for channel from nick
verify-requests [-server <server>] [<nick>]          Check signature of incomming key requests
verify-keys     [-server <server>] [<nick>]          Check signature of received keys
plain           [-server <s>] [-channel <ch>] <msg>  Send unencrypted message


%(bold)sExamples: %(normal)s

Set the key for a channel:
  /ircrypt set-key -server freenet #IRCrypt key
Remove the key:
  /ircrypt remove-key #IRCrypt
Set the key for a user:
  /ircrypt set-key nick key
Set the public key identifier for a user:
  /ircrypt set-gpg-id -server freenode nick Id
Remove public key identifier for a user:
  /ircrypt remove-gpg-id nick
Switch to a specific cipher for a channel:
  /ircrypt set-cipher -server freenode #IRCrypt TWOFISH
Unset the specific cipher for a channel:
  /ircrypt remove-cipher #IRCrypt
Send unencrypted “Hello” to current channel
  /ircrypt plain Hello


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
%(bold)sircrypt.cipher.asym_enabled %(normal)s
   This enables asymmetric encryption which can be used for encrypted
   communication without key exchange. It is only required that the public key
   identifier of the communication partner is set.
%(bold)sircrypt.cipher.exchange_enabled %(normal)s
   This option enables key exchange based on GPG and its public key
   infrastructure. During a key exchange the identity of both communication
   partners can be verified and finally, a key can be exchanged on a secure
   way.
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


def ircrypt_public_key_send(server, args, info):
	global ircrypt_gpg_homedir, ircrypt_gpg_id

	if ircrypt_gpg_id:
		p = subprocess.Popen([ircrypt_gpg_binary, '--batch', '--no-tty',
			'--quiet', '--homedir', ircrypt_gpg_homedir,'--export',
			ircrypt_gpg_id], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
		(key, err) = p.communicate()

		if err:
			weechat.prnt('', err)

		key = base64.b64encode(key)

	for i in range(1 + (len(key) / 400))[::-1]:
		msg = '>KCRY-%i %s' % (i, key[i*400:(i+1)*400])
		weechat.command('','/mute -all notice -server %s %s %s' % (server, info['nick'], msg))
	return ''


def ircrypt_public_key_get(server, args, info):
	global ircrypt_keys_buffer, ircrypt_asym_id

	# Get prefix, number and message
	pre, message    = args.split('>KCRY-', 1)
	number, message = message.split(' ', 1)

	# Get key for the request buffer
	buf_key = (server, info['channel'], info['nick'])

	# Check if we got the last part of the message otherwise put the message
	# into a global buffer and quit
	if int(number):
		if not buf_key in ircrypt_keys_buffer:
			# - First element is list of requests
			# - Second element is currently received request
			ircrypt_keys_buffer[buf_key] = MessageParts()
		# Add parts to current request
		ircrypt_keys_buffer[buf_key].update(int(number), message)
		return ''
	else:
		target = ('%s/%s' % (server, info['nick'])).lower()
		# check asymmetric key id
		key_id = ircrypt_asym_id.get(target)
		if key_id:
			weechat.prnt('', 'WARNING There exist a gpg key for this user. Nothing changed')
			return ''

		p = subprocess.Popen([ircrypt_gpg_binary, '--no-tty',
			'--homedir', ircrypt_gpg_homedir, '--keyid-format', '0xlong',
			'--import'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
		(out, err) = p.communicate(base64.b64decode(message +
			ircrypt_keys_buffer[buf_key].message))

		weechat.prnt('', err)

		try:
			gpg_id = err.split('0x',1)[1].split(':',1)[0]
		except:
			weechat.prnt('', 'Unable to get key id')
			return ''

		# Probe for GPG fingerprint
		p = subprocess.Popen([ircrypt_gpg_binary, '--homedir', ircrypt_gpg_homedir,
			'--batch', '--no-tty', '--quiet', '--fingerprint', '--with-colon'],
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(out, err) = p.communicate()

		# There is a secret key
		if out:
			out = [ line for line in out.split('\n') \
					if (gpg_id + ':') in line and line.startswith('fpr:') ][-1]
			gpg_id = out.split('fpr')[-1].strip(':')

		# Set asymmetric identifier
		ircrypt_asym_id[target.lower()] = gpg_id
		# Print status message in current buffer
		weechat.prnt('', 'Set gpg key for %s' % target)
		ircrypt_sym_ex(server, info['nick'])
		return ''


def ircrypt_sym_ex(server, nick):
	global ircrypt_asym_id
	key = os.urandom(64)
	target = '%s/%s' % (server, nick)
	p = subprocess.Popen([ircrypt_gpg_binary, '--homedir', ircrypt_gpg_homedir,
		'--batch', '--no-tty', '--quiet', '-s', '--trust-model', 'always', '-e',
		'-r', ircrypt_asym_id[target]], stdin=subprocess.PIPE,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(out, err) = p.communicate(key)
	if err:
		weechat.prnt('', err)
	out = base64.b64encode(out)
	for i in range(1 + (len(out) / 400))[::-1]:
		msg = '>KEY-EX-%i %s' % (i, out[i*400:(i+1)*400])
		weechat.command('','/mute -all notice -server %s %s %s' % (server, nick, msg))


def ircrypt_query_pong(server, args, info):
	global ircrypt_gpg_id
	fingerprint = args.split('>KEY-EX-PING')[-1].lstrip(' ')
	if fingerprint and fingerprint != ircrypt_gpg_id:
		weechat.command('','/mute -all notice -server %s %s >UCRY-PING-WITH-INVALID-FINGERPRINT' \
				% (server, info['nick']))
		return ''
	target = '%s/%s' % (server, info['nick'])
	gpg_id = ircrypt_asym_id.get(target.lower())
	if gpg_id:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PONG %s' \
				% (server, info['nick'], gpg_id))
	else:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PONG' \
				% (server, info['nick']))
	if not fingerprint:
		return ircrypt_public_key_send(server, args, info)
	return ''


def ircrypt_pong_pong(server, args, info):
	global ircrypt_gpg_id
	fingerprint = args.split('>KEY-EX-PONG')[-1].lstrip(' ')
	if fingerprint and fingerprint != ircrypt_gpg_id:
		weechat.command('','/mute -all notice -server %s %s >UCRY-PING-WITH-INVALID-FINGERPRINT' \
				% (server, info['nick']))
		return ''
	if fingerprint:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-CONTINUE' \
				% (server, info['nick']))
		ircrypt_sym_ex(server, info['nick'])
		return ''
	return ircrypt_public_key_send(server, args, info)


def ircrypt_pong_pong_pong(server, args, info):
	global ircrypt_gpg_id
	target = '%s/%s' % (server, info['nick'])
	gpg_id = ircrypt_asym_id.get(target.lower())
	if gpg_id:
		ircrypt_sym_ex(server, info['nick'])
	return ''


def ircrypt_decrypt_hook(data, msgtype, server, args):
	'''Hook for incomming PRVMSG commands.
	This method will parse the input, check if it is an encrypted message and
	call the appropriate decryption methods if necessary.

	:param data:
	:param msgtype:
	:param server: IRC server the message comes from.
	:param args: IRC command line-
	'''
	global ircrypt_config_option, ircrypt_keys, ircrypt_asym_id

	info = weechat.info_get_hashtable('irc_message_parse', { 'message': args })

	# asymmetric encryption
	if '>ACRY-' in args:
		return ircrypt_decrypt_asym(server, args, info)

	# Check if channel is own nick and if change channel to nick of sender
	if info['channel'][0] not in '#&':
		info['channel'] = info['nick']

	# Get key
	key = ircrypt_keys.get(('%s/%s' % (server, info['channel'])).lower())
	if key:
		# if key exists and >CRY part of message start symmetric encryption
		if '>CRY-' in args:
			return ircrypt_decrypt_sym(server, args, info, key)
		# if key exisits and no >CRY not part of message flag message as unencrypted
		else:
			pre, message = string.split(args, ' :', 1)
			return '%s :%s %s' % (pre,
					weechat.config_string(ircrypt_config_option['unencrypted']),
					message)

	# If no asymmetric or symmetric encryption return arguments
	return args


def ircrypt_decrypt_sym(server, args, info, key):
	'''This method is called to decrypt an symmetric encrypted messages and put
	them together again if necessary.

	:param server: IRC server the message comes from.
	:param args: IRC command line-
	:param info: dictionary created by info_get_hashtable
	:param key: key for decryption
	'''
	global ircrypt_msg_buffer, ircrypt_config_option

	pre, message    = string.split(args, '>CRY-', 1)
	number, message = string.split(message, ' ', 1 )

	# Get key for the message buffer
	buf_key = '%s.%s.%s' % (server, info['channel'], info['nick'])

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

	# Get message buffer in case we need to print an error
	buf = weechat.buffer_search('irc', '%s.%s' % (server,info['channel']))

	# Decode base64 encoded message
	try:
		message = base64.b64decode(message)
	except TypeError:
		weechat.prnt(buf, '%s%sCould not Base64 decode message.' %
				(weechat.prefix('error'), weechat.color('red')))
		return args

	# Decrypt
	p = subprocess.Popen([ircrypt_gpg_binary, '--batch',  '--no-tty', '--quiet',
		'--passphrase-fd', '-', '-d'],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	decrypted, err = p.communicate('%s\n%s' % (key, message))

	# Get and print GPG errors/warnings
	err = '\n'.join(['  ▼ ' + line for line in err.split('\n') if line])
	if p.returncode:
		weechat.prnt(buf, '%s%s%s' %
				(weechat.prefix('error'), weechat.color('red'), err))
		return args
	elif err:
		weechat.prnt(buf, '%s%s' % (weechat.color('gray'), err))

	# Remove old messages from buffer
	try:
		del ircrypt_msg_buffer[buf_key]
	except KeyError:
		pass
	return '%s%s' % (pre, decrypted)


def ircrypt_decrypt_asym(server, args, info):
	'''This method is called to decrypt an asymmetric encrypted messages and put
	them together again if necessary.

	:param server: IRC server the message comes from.
	:param args: IRC command line-
	:param info: dictionary created by info_get_hashtable
	'''
	global ircrypt_msg_buffer, ircrypt_config_option

	# Get prefix, number and message
	pre, message    = string.split(args, '>ACRY-', 1)
	number, message = string.split(message, ' ', 1 )

	# Get key for the message buffer
	buf_key = '%s.%s.%s' % (server, info['channel'], info['nick'])

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

	# Get message buffer in case we need to print an error
	buf = weechat.buffer_search('irc', '%s.%s' % (server,info['channel']))

	# Decrypt
	p = subprocess.Popen([ircrypt_gpg_binary, '--batch',  '--no-tty',
		'--quiet', '--homedir', ircrypt_gpg_homedir, '-d'],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	p.stdin.write(base64.b64decode(message))
	p.stdin.close()
	decrypted = p.stdout.read()
	p.stdout.close()

	# Get and print GPG errors/warnings
	err = p.stderr.read()
	p.stderr.close()
	if err:
		weechat.prnt(buf, 'GPG reported error:\n%s' % err)

	# Remove old messages from buffer
	try:
		del ircrypt_msg_buffer[buf_key]
	except KeyError:
		pass
	return '%s%s' % (pre, decrypted)


def ircrypt_encrypt_hook(data, msgtype, server, args):
	'''Hook for outgoing PRVMSG commands.
	This method will call the appropriate methods for encrypting the outgoing
	messages either symmetric or asymmetric

	:param data:
	:param msgtype:
	:param server: IRC server the message comes from.
	:param args: IRC command line-
	'''
	global ircrypt_keys, ircrypt_asym_id
	info = weechat.info_get_hashtable("irc_message_parse", { "message": args })

	# check if this message is to be send as plain text
	plain = ircrypt_message_plain.get('%s/%s' % (server, info['channel']))
	if plain:
		del ircrypt_message_plain['%s/%s' % (server, info['channel'])]
		if (plain[0] - time.time()) < 5 \
				and args == 'PRIVMSG %s :%s' % (info['channel'], plain[1]):
			args = args.replace('PRIVMSG %s :%s ' % (
				info['channel'],
				weechat.config_string(ircrypt_config_option['unencrypted'])),
				'PRIVMSG %s :' % info['channel'])
			return args

	# check symmetric key
	key = ircrypt_keys.get(('%s/%s' % (server, info['channel'])).lower())
	if key:
		return ircrypt_encrypt_sym(server, args, info, key)

	# check asymmetric key id
	key_id = ircrypt_asym_id.get(('%s/%s' % (server, info['channel'])).lower())
	if key_id and weechat.config_boolean(
				weechat.config_get('ircrypt.cipher.asym_enabled')):
		return ircrypt_encrypt_asym(server, args, info, key_id)

	# No key -> don't encrypt
	return args


def ircrypt_encrypt_sym(server, args, info, key):
	'''This method will symmetric encrypt messages and if necessary (if
	they grow to large) split them into multiple parts.

	:param server: IRC server the message comes from.
	:param args: IRC command line-
	:param info: dictionary created by info_get_hashtable
	:param key: key for decryption
	'''

	global ircrypt_cipher

	# Get cipher
	cipher = ircrypt_cipher.get(('%s/%s' % (server, info['channel'])).lower(),
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
		buf = weechat.buffer_search('irc', '%s.%s' % (server, info['channel']))
		weechat.prnt(buf, 'GPG reported error:\n%s' % err)

	#create output
	output = '%s:>CRY-0 %s' % (pre, encrypted)
	# Check if encrypted message is to long.
	# If that is the case, send multiple messages.
	if len(output) > MAX_PART_LEN:
		output = '%s:>CRY-1 %s\r\n%s' % (pre, output[MAX_PART_LEN:],
				output[:MAX_PART_LEN])
	return output


def ircrypt_encrypt_asym(server, args, info, key_id):
	'''This method will asymmetric encrypt messages and if necessary (if
	they grow to large) split them into multiple parts.

	:param server: IRC server the message comes from.
	:param args: IRC command line-
	:param info: dictionary created by info_get_hashtable
	:param key_id : key_id
	'''

	# Get prefix and message
	pre, message = string.split(args, ':', 1)

	# Encrypt message
	p = subprocess.Popen([ircrypt_gpg_binary, '--batch',  '--no-tty',
		'--quiet', '--homedir', ircrypt_gpg_homedir, '--trust-model', 'always', '-e', '-r', key_id],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	p.stdin.write(message)
	p.stdin.close()
	encrypted = base64.b64encode(p.stdout.read())
	p.stdout.close()

	# Get and print GPG errors/warnings
	err = p.stderr.read()
	p.stderr.close()
	if err:
		buf = weechat.buffer_search('irc', '%s.%s' % (server, info['channel']))
		weechat.prnt(buf, 'GPG reported error:\n%s' % err)

	# Send encrypted message in MAX_PART_LEN sized blocks
	return '\n'.join(['%s:>ACRY-%i %s' % (pre, i,
		encrypted[i*MAX_PART_LEN:(i+1) * MAX_PART_LEN])
		for i in xrange(1 + (len(encrypted) / MAX_PART_LEN))][::-1])


def ircrypt_config_init():
	''' This method initializes the configuration file. It creates sections and
	options in memory and prepares the handling of key sections.
	'''
	global ircrypt_config_file, ircrypt_config_section, ircrypt_config_option
	ircrypt_config_file = weechat.config_new('ircrypt', 'ircrypt_config_reload_cb', '')
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
	ircrypt_config_option['asym_enabled'] = weechat.config_new_option(
			ircrypt_config_file, ircrypt_config_section['cipher'], 'asym_enabled',
			'boolean', 'If asymmetric encryption is used for message encryption',
			'', 0, 0,
			'off', 'off', 0, '', '', '', '', '', '')
	ircrypt_config_option['exchange_enabled'] = weechat.config_new_option(
			ircrypt_config_file, ircrypt_config_section['cipher'], 'exchange_enabled',
			'boolean', 'If key exchange is enabled',
			'', 0, 0,
			'off', 'off', 0, '', '', '', '', '', '')

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

	# Asymmetric key identifier
	ircrypt_config_section['asym_id'] = weechat.config_new_section(
			ircrypt_config_file, 'asym_id', 0, 0,
			'ircrypt_config_asym_id_read_cb', '',
			'ircrypt_config_asym_id_write_cb', '', '', '', '', '', '', '')
	if not ircrypt_config_section['asym_id']:
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
	ircrypt_init()
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

	ircrypt_keys[option_name.lower()] = value
	return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED


def ircrypt_config_keys_write_cb(data, config_file, section_name):
	'''Write passphrases to the key section of the configuration file.
	'''
	global ircrypt_keys

	weechat.config_write_line(config_file, section_name, '')
	for target, key in sorted(ircrypt_keys.iteritems()):
		weechat.config_write_line(config_file, target.lower(), key)

	return weechat.WEECHAT_RC_OK

def ircrypt_config_asym_id_read_cb(data, config_file, section_name, option_name,
		value):
	'''Read elements of the key section from the configuration file.
	'''
	global ircrypt_asym_id

	if not weechat.config_new_option(config_file, section_name, option_name,
			'string', 'asym_id', '', 0, 0, '', value, 0, '', '', '', '', '', ''):
		return weechat.WEECHAT_CONFIG_OPTION_SET_ERROR

	ircrypt_asym_id[option_name.lower()] = value
	return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED


def ircrypt_config_asym_id_write_cb(data, config_file, section_name):
	'''Write passphrases to the key section of the configuration file.
	'''
	global ircrypt_asym_id

	weechat.config_write_line(config_file, section_name, '')
	for target, asym_id in sorted(ircrypt_asym_id.iteritems()):
		weechat.config_write_line(config_file, target.lower(), asym_id)

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

	ircrypt_cipher[option_name.lower()] = value
	return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED


def ircrypt_config_special_cipher_write_cb(data, config_file, section_name):
	'''Write passphrases to the key section of the configuration file.
	'''
	global ircrypt_cipher

	weechat.config_write_line(config_file, section_name, '')
	for target, cipher in sorted(ircrypt_cipher.iteritems()):
		weechat.config_write_line(config_file, target.lower(), cipher)

	return weechat.WEECHAT_RC_OK


def ircrypt_command_list():
	'''ircrypt command to list the keys, asymmetric identifier and Special Cipher'''

	global ircrypt_keys, ircrypt_asym_id, ircrypt_cipher

	# Get buffer
	buffer = weechat.current_buffer()
	# Print keys, asymmetric identifier and special cipher in current buffer
	weechat.prnt(buffer,'\nKeys:')
	for servchan,key in ircrypt_keys.iteritems():
		weechat.prnt(buffer,'%s : %s' % (servchan.lower(), key))

	weechat.prnt(buffer,'\nAsymmetric identifier:')
	for servchan,ids in ircrypt_asym_id.iteritems():
		weechat.prnt(buffer,'%s : %s' % (servchan.lower(), ids))

	weechat.prnt(buffer,'\nSpecial Cipher:')
	for servchan,spcip in ircrypt_cipher.iteritems():
		weechat.prnt(buffer,'%s : %s' % (servchan.lower(), spcip))

	weechat.prnt(buffer,'\n')
	return weechat.WEECHAT_RC_OK


def ircrypt_command_set_keys(target, key):
	'''ircrypt command to set key for target (target is a server/channel combination)'''
	global ircrypt_keys
	# Set key
	ircrypt_keys[target.lower()] = key
	# Print status message to current buffer
	weechat.prnt(weechat.current_buffer(),'Set key for %s' % target)
	return weechat.WEECHAT_RC_OK


def ircrypt_command_remove_keys(target):
	'''ircrypt command to remove key for target (target is a server/channel combination)'''
	global ircrypt_keys
	# Get buffer
	buffer = weechat.current_buffer()
	# Check if key is set and print error in current buffer otherwise
	if target.lower() not in ircrypt_keys:
		weechat.prnt(buffer, 'No existing key for %s.' % target)
		return weechat.WEECHAT_RC_OK
	# Delete key and print status message in current buffer
	del ircrypt_keys[target.lower()]
	weechat.prnt(buffer, 'Removed key for %s' % target)
	return weechat.WEECHAT_RC_OK


def ircrypt_command_set_cip(target, cipher):
	'''ircrypt command to set key for target (target is a server/channel combination)'''
	global ircrypt_cipher
	# Set special cipher
	ircrypt_cipher[target.lower()] = cipher
	# Print status message in current buffer
	weechat.prnt(weechat.current_buffer(),'Set cipher %s for %s' % (cipher, target))
	return weechat.WEECHAT_RC_OK

def ircrypt_command_remove_cip(target):
	'''ircrypt command to remove key for target (target is a server/channel combination)'''
	global ircrypt_cipher
	# Get buffer
	buffer = weechat.current_buffer()
	# Check if special cipher is set and print error in current buffer otherwise
	if target.lower() not in ircrypt_cipher:
		weechat.prnt(buffer, 'No special cipher set for %s.' % target)
		return weechat.WEECHAT_RC_OK
	# Delete special cipher and print status message in current buffer
	del ircrypt_cipher[target.lower()]
	weechat.prnt(buffer, 'Removed special cipher. Use default cipher for %s instead.' % target)
	return weechat.WEECHAT_RC_OK


def ircrypt_command_query(server, nick):
	'''This function ist called when the user starts a key exchange'''
	global ircrypt_asym_id
	target = '%s/%s' % (server, nick)
	gpg_id = ircrypt_asym_id.get(target.lower())
	if gpg_id:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PING %s' \
				% (server, nick, gpg_id))
	else:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PING' \
				% (server, nick))
	weechat.command('','/query -server %s %s' % (server, nick))
	weechat.prnt(weechat.current_buffer(), 'Start key exchange with %s on server %s' % \
			(nick, server))
	return weechat.WEECHAT_RC_OK


def ircrypt_command_request_public_key(server, nick):
	'''This function ist called when the user requests a key from another
	user'''
	weechat.command('','/mute -all notice -server %s %s >KEY-REQUEST' \
			% (server, nick))
	# Print message in ircrypt buffer, that request was declined
	weechat.prnt('', 'Request public gpg-key from user %s on server %s' % \
			(nick, server))
	return weechat.WEECHAT_RC_OK


def ircrypt_command_remove_public_key(target):
	'''ircrypt command to remove public key for target (target is a server/channel combination)'''
	global ircrypt_asym_id
	# Get buffer
	buffer = weechat.current_buffer()
	# Check if public key is set and print error in current buffer otherwise
	if target.lower() not in ircrypt_asym_id:
		weechat.prnt(buffer, 'No existing public key for %s.' % target)
		return weechat.WEECHAT_RC_OK
	# Delete public key (first in gpg then in config file) and print status message in current buffer
	p = subprocess.Popen([ircrypt_gpg_binary, '--batch', '--yes', '--no-tty',
		'--quiet', '--homedir', ircrypt_gpg_homedir,'--delete-key',
		ircrypt_asym_id[target.lower()]], stdin=subprocess.PIPE,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(out, err) = p.communicate()
	if p.returncode:
		weechat.prnt(buffer, 'Could not delete public key in gpg')
	del ircrypt_asym_id[target.lower()]
	weechat.prnt(buffer, 'Removed asymmetric identifier for %s' % target)
	return weechat.WEECHAT_RC_OK


def ircrypt_command(data, buffer, args):
	'''Hook to handle the /ircrypt weechat command. This method is also used for
	all commands typed into the IRCrypt buffer.
	'''
	global ircrypt_keys, ircrypt_asym_id, ircrypt_cipher

	argv = [a for a in args.split(' ') if a]

	if argv and not argv[0] in ['list', 'buffer', 'set-key', 'remove-key',
			'remove-public-key', 'set-cipher', 'remove-cipher', 'exchange',
			'plain', 'request-public-key', 'query']:
		weechat.prnt(buffer, '%sUnknown command. Try  /help ircrypt' % \
				weechat.prefix('error'))
		return weechat.WEECHAT_RC_OK

	# list
	if not argv or argv == ['list']:
		return ircrypt_command_list()

	# Check if a server was set
	if (len(argv) > 2 and argv[1] == '-server'):
		server = argv[2]
		del argv[2]
		del argv[1]
		args = args.split(' ', 2)[-1]
	else:
		# Try to determine the server automatically
		server = weechat.buffer_get_string(buffer, 'localvar_server')

	# All remaining commands need a server name
	if not server:
		# if no server was set print message in ircrypt buffer and throw error
		weechat.prnt(buffer, 'Unknown Server. Please use -server to specify server')
		return weechat.WEECHAT_RC_ERROR

	if argv[:1] == ['plain']:
		channel = ''
		if (len(argv) > 2 and argv[1] == '-channel'):
			channel = argv[2]
			del argv[2]
			del argv[1]
			args = args.split(' ', 2)[-1]
		else:
			# Try to determine the server automatically
			channel = weechat.buffer_get_string(buffer, 'localvar_channel')
		marker = weechat.config_string(ircrypt_config_option['unencrypted'])
		msg = marker + ' ' + args.split(' ', 1)[-1]
		ircrypt_message_plain['%s/%s' % (server, channel)] = (time.time(), msg)
		weechat.command('','/msg -server %s %s %s' % \
				(server, channel, msg))
		return weechat.WEECHAT_RC_OK

	# For the remaining commands we need at least one additional argument
	if len(argv) < 2:
		return weechat.WEECHAT_RC_ERROR

	target = '%s/%s' % (server, argv[1])

	if argv[0] == 'query':
		if len(argv) == 2:
			return ircrypt_command_query(server, argv[1])
		return weechat.WEECHAT_RC_ERROR

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

	# Request public key from another user
	if argv[0] == 'request-public-key':
		if len(argv) != 2:
			return weechat.WEECHAT_RC_ERROR
		return ircrypt_command_request_public_key(server, argv[1])

	# Remove public key from another user
	if argv[0] == 'remove-public-key':
		if len(argv) != 2:
			return weechat.WEECHAT_RC_ERROR
		return ircrypt_command_remove_public_key(target)

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
	key = ircrypt_keys.get(('%s/%s' % (server, channel)).lower())

	# Return nothing if no key is set for current channel
	if not key:
		return ''

	# Return marer, but replace {{cipher}} with used cipher for current channel
	return weechat.config_string(ircrypt_config_option['encrypted']).replace(
			'{{cipher}}', ircrypt_cipher.get(('%s/%s' % (server, channel)).lower(),
				weechat.config_string(ircrypt_config_option['sym_cipher'])))


def ircrypt_notice_hook(data, msgtype, server, args):

	info = weechat.info_get_hashtable('irc_message_parse', { 'message': args })

	# Check for error messages
	if '>UCRY-' in args:
		# TODO: Add error handler
		return args

	if '>KEY-EX-PING' in args:
		return ircrypt_query_pong(server, args, info)

	if '>KEY-EX-PONG' in args:
		return ircrypt_pong_pong(server, args, info)

	if '>KEY-REQUEST' in args:
		return ircrypt_public_key_send(server, args, info)

	if '>KCRY-' in args:
		return ircrypt_public_key_get(server, args, info)

	if '>KEY-EX-CONTINUE' in args:
		return ircrypt_pong_pong_pong(server, args, info)

	return args


def ircrypt_find_gpg_binary(names=('gpg2','gpg')):
	'''Check for GnuPG binary to use
	:returns: Tuple with binary name and version.
	'''
	for binary in names:
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
	if not ircrypt_gpg_binary:
		ircrypt_gpg_binary,version = ircrypt_find_gpg_binary(('gpg','gpg2'))
		if not ircrypt_gpg_binary:
			weechat.prnt('', '%sAutomatic detection of the GnuPG binary failed and '
					'nothing is set manually. You wont be able to use IRCrypt like '
					'this. Please install GnuPG or set the path to the binary to '
					'use.' % weechat.prefix('error'))
		else:
			weechat.prnt('', 'Found %s' % version)
			weechat.config_option_set(ircrypt_config_option['binary'], ircrypt_gpg_binary, 1)


def ircrypt_init():
	global ircrypt_gpg_homedir, ircrypt_gpg_id
	# This should usually be ~/.weechat/ircrypt
	ircrypt_gpg_homedir = '%s/ircrypt' % weechat.info_get("weechat_dir", "")
	# make sure only the current user has access
	oldmask = os.umask(077)
	try:
		os.mkdir(ircrypt_gpg_homedir)
	except OSError:
		pass
	os.umask(oldmask)

	# Probe for GPG key
	p = subprocess.Popen([ircrypt_gpg_binary, '--homedir', ircrypt_gpg_homedir,
		'--batch', '--no-tty', '--quiet', '--list-secret-keys',
		'--with-fingerprint', '--with-colon'], stdin=subprocess.PIPE,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(out, err) = p.communicate()


	# There is a secret key
	if out:
		try:
			ircrypt_gpg_id = out.split('fpr')[-1].split('\n')[0].strip(':')
			weechat.prnt('', 'IRCrypt: Found private gpg key with id %s' % ircrypt_gpg_id)
			return weechat.WEECHAT_RC_OK
		except:
			weechat.prnt('', '%sIRCrypt: Unable to get key id', weechat.prefix('error'))

	# Try to generate a key
	weechat.prnt('', '%sIRCrypt Notice:%s' % \
			(weechat.color('bold'), weechat.color('-bold')))
	weechat.prnt('', 'No private key for assymetric encryption was found in the '
			+ 'IRCrypt GPG keyring. IRCrypt will now try to automatically generate a '
			+ 'new key. This might take quite some time as this procedure depends on '
			+ 'the gathering of enough entropy for generating cryptographically '
			+ 'strong random numbers. You cannot use the asymmetric encryption '
			+ '(private chat encryption) until this process is done. However, it does '
			+ 'not affect the symmetric encryption which can already be used. You '
			+ 'will be notified once the process is done.')
	hook = weechat.hook_process_hashtable(ircrypt_gpg_binary, {
		'stdin': '1',
		'arg1': '--batch',
		'arg2': '--no-tty',
		'arg3': '--quiet',
		'arg4': '--homedir',
		'arg5': ircrypt_gpg_homedir,
		'arg6': '--gen-key'},
		0, 'ircrypt_key_generated_cb', '')
	gen_command = 'Key-Type: RSA\n' \
			+ 'Key-Length: 2048\n' \
			+ 'Subkey-Type: RSA\n' \
			+ 'Subkey-Length: 2048\n' \
			+ 'Name-comment: ircrypt\n' \
			+ 'Expire-Date: 0\n' \
			+ '%commit'

	weechat.hook_set(hook, 'stdin', gen_command)
	weechat.hook_set(hook, 'stdin_close', '')
	return weechat.WEECHAT_RC_OK

def ircrypt_key_generated_cb(data, command, errorcode, out, err):
	if errorcode:
		weechat.prnt('','%sIRCrypt: Could not generate key' % \
				weechat.prefix('error'))
		return weechat.WEECHAT_RC_OK

	weechat.prnt('', '%sIRCrypt Notice:%s' % \
			(weechat.color('bold'), weechat.color('-bold')))
	weechat.prnt('', 'A private key for assymetric encryption was successfully'
			+ 'generated and can now be used for communication.')
	return ircrypt_init()


# register plugin
if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
		SCRIPT_DESC, 'ircrypt_unload_script', 'UTF-8'):
	# register the modifiers
	weechat.hook_modifier('irc_in_privmsg',  'ircrypt_decrypt_hook', '')
	weechat.hook_modifier('irc_out_privmsg', 'ircrypt_encrypt_hook', '')
	weechat.hook_modifier('irc_in_notice',   'ircrypt_notice_hook', '')

	weechat.hook_command('ircrypt', 'Manage IRCrypt Keys and public key identifier',
			'[list] '
			'| buffer '
			'| set-key [-server <server>] <target> <key> '
			'| remove-key [-server <server>] <target> '
			'| request-public-key [-server <server>] <nick>'
			'| remove-public-key [-server <server>] <nick> '
			'| set-cipher [-server <server>] <target> <cipher> '
			'| remove-cipher [-server <server>] <target> '
			'| exchange [-server <server>] <nick> [<target>] '
			'| verify-requests [-server <server>] [<nick>] '
			'| verify-keys [-server <server>] [<nick>] '
			'| plain [-server <server>] [-channel <channel>] <message>',
			ircrypt_help_text,
			'list || buffer || set-key %(irc_channel)|%(nicks)|-server %(irc_servers) %- '
			'|| remove-key %(irc_channel)|%(nicks)|-server %(irc_servers) %- '
			'|| exchange %(nicks) %(irc_channel) -server %(irc_servers)'
			'|| verify-requests %(nicks)|-server %(irc_servers) %- '
			'|| verify-keys %(nicks)|-server %(irc_servers) %- '
			'|| request-public-key %(nicks)|-server %(irc_servers) %- '
			'|| remove-public-key %(nicks)|-server %(irc_servers) %- '
			'|| set-cipher %(irc_channel)|-server %(irc_servers) %- '
			'|| remove-cipher |%(irc_channel)|-server %(irc_servers) %- '
			'|| plain |-channel %(irc_channel)|-server %(irc_servers) %-',
			'ircrypt_command', '')

	ircrypt_config_init()
	ircrypt_config_read()
	ircrypt_check_binary()
	ircrypt_init()
	weechat.bar_item_new('ircrypt', 'ircrypt_encryption_statusbar', '')
	weechat.hook_signal('ircrypt_buffer_opened', 'update_encryption_status', '')


def ircrypt_unload_script():
	'''Hook to ensure the configuration is properly written to disk when the
	script is unloaded.
	'''
	ircrypt_config_write()
	return weechat.WEECHAT_RC_OK
