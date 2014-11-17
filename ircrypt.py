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


# Global memory used to store message parts, pending requests, configuration
# options, keys, etc.
ircrypt_msg_memory       = {}
ircrypt_config_file      = None
ircrypt_config_section   = {}
ircrypt_config_option    = {}
ircrypt_keys             = {}
ircrypt_asym_id          = {}
ircrypt_cipher           = {}
ircrypt_pub_keys_memory  = {}
ircrypt_sym_keys_memory  = {}
ircrypt_key_ex_memory    = {}
ircrypt_gpg_binary       = None
ircrypt_message_plain    = {}
ircrypt_gpg_homedir      = None
ircrypt_gpg_id           = None

# Constants used throughout this script
MAX_PART_LEN     = 300
MSG_PART_TIMEOUT = 300 # 5min
KEY_PART_TIMEOUT = 100
NEVER            = 0
ALWAYS           = 1
IF_NEW           = 2


ircrypt_help_text = '''%(bold)sIRCrypt command options: %(normal)s
list                                                    List set keys, public key ids and ciphers
set-key            [-server <server>] <target> <key>    Set key for target
remove-key         [-server <server>] <target>          Remove key for target
query              [-server <server>] <nick>            Start key exchange with nick
set-cipher         [-server <server>] <target> <cipher> Set specific cipher for target
remove-cipher      [-server <server>] <target>          Remove specific cipher for target
remove-public-key  [-server <server>] <nick>            Remove public key id for nick
plain              [-server <s>] [-channel <ch>] <msg>  Send unencrypted message

%(bold)sExamples: %(normal)s
Set the key for a channel:
   /ircrypt set-key -server freenet #IRCrypt key
Remove the key:
   /ircrypt remove-key #IRCrypt
Start key exchange with a user
   /ircrypt query nick
Remove public key identifier for a user:
   /ircrypt remove-public-key nick
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
   If you add 'ircrypt' to weechat.bar.status.items, these option will set a
   string which is displayed in the status bar of an encrypted channels,
   indicating that the current channel is encrypted.
   If “{{cipher}}” is used as part of this string, it will be replaced by the
   cipher currently used by oneself for that particular channel.
   It is woth noting that you probably don't want to replace the whole value of
   that option but extend it instead in a way like:
      /set weechat.bar.status.items {{currentContent}},ircrypt
%(bold)sircrypt.marker.unencrypted %(normal)s
   This option will set a string which is displayed before each message that is
   send unencrypted in a channel for which a key is set. So you know when
   someone is talking to you without encryption.
%(bold)sircrypt.cipher.sym_cipher %(normal)s
   This will set the default cipher used for symmetric encryption. You can get
   a list of available ciphers by running “gpg --version”.
%(bold)sircrypt.general.binary %(normal)s
   This will set the GnuPG binary used for encryption and decryption. IRCrypt
   will try to set this automatically.
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


class SymKeyParts:
	'''Class used for storing parts of symmetric keys which were generate by two
	userns.'''

	modified = 0
	parts = 0
	key  = ''

	def update(self, keypart):
		'''This method updates an already existing message part by adding a new
		part to the old ones and updating the identifier of the latest received
		message part.
		'''
		if time.time() - self.modified > KEY_PART_TIMEOUT or self.parts > 1:
			self.key = ''
			self.parts = 0
		if self.key == '':
			self.key = keypart
		else:
			self.key = ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(self.key, keypart))
		self.parts = self.parts + 1
		self.modified = time.time()


class KeyExchange:
	'''Class used for key exchange'''

	phase = 1
	pub_key_get = False
	pub_key_send = False
	parts = 0
	sym_key  = ''

	def __init__(self, pub_key_get, pub_key_send):
		self.pub_key_get = pub_key_get
		self.pub_key_send = pub_key_send

	def update(self, keypart):
		if self.sym_key == '':
			self.sym_key = keypart
		else:
			self.sym_key = ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(self.sym_key, keypart))
		self.parts = self.parts + 1

def ircrypt_receive_key_ex_ping(server, args, info):
	'''This function handles incomming >KEY-EX-PING notices'''
	global ircrypt_gpg_id, ircrypt_key_ex_memory
	fingerprint = args.split('>KEY-EX-PING')[-1].lstrip(' ')
	# Wrong fingerprint: Send back and error
	if fingerprint and fingerprint != ircrypt_gpg_id:
		weechat.command('','/mute -all notice -server %s %s >UCRY-PING-WITH-INVALID-FINGERPRINT' \
				% (server, info['nick']))
		return ''
	# Send back a >KEY-EX-PONG inclusive a fingerprint (if exist)
	# Also create an instance of the class KeyExchange to save, whether the public
	# keys have already been exchanged
	target = '%s/%s' % (server, info['nick'])
	gpg_id = ircrypt_asym_id.get(target.lower())
	if gpg_id:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PONG %s' \
				% (server, info['nick'], gpg_id))
		if fingerprint:
			ircrypt_key_ex_memory[target] = KeyExchange(True, True)
		else:
			ircrypt_key_ex_memory[target] = KeyExchange(True, False)
	else:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PONG' \
				% (server, info['nick']))
		if fingerprint:
			ircrypt_key_ex_memory[target] = KeyExchange(False, True)
		else:
			ircrypt_key_ex_memory[target] = KeyExchange(False, False)
	return ''


def ircrypt_receive_key_ex_pong(server, args, info):
	'''This function handles incomming >KEY-EX-PONG notices'''

	global ircrypt_gpg_id, ircrypt_key_ex_memory
	fingerprint = args.split('>KEY-EX-PONG')[-1].lstrip(' ')
	target = '%s/%s' % (server, info['nick'])
	# Wrong fingerprint: Send back and error and try to delete instance of class
	# KeyExchange
	if fingerprint and fingerprint != ircrypt_gpg_id:
		weechat.command('','/mute -all notice -server %s %s >UCRY-PING-WITH-INVALID-FINGERPRINT' \
				% (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''
	# Send back a >KEY-EX-NEXT-PHASE to continue key exchange or send back a
	# error. Continue with phase 2 or 3 of Also save, whether the public keys have already been exchanged
	if ircrypt_key_ex_memory.get(target):
		if fingerprint:
			ircrypt_key_ex_memory[target].pub_key_send = True
		if ircrypt_key_ex_memory[target].pub_key_send and ircrypt_key_ex_memory[target].pub_key_get:
			ircrypt_key_ex_memory[target].phase = 3
			weechat.command('','/mute -all notice -server %s %s >KEY-EX-NEXT-PHASE-3' \
					% (server, info['nick']))
			ircrypt_sym_key_send(server, info['nick'])
		else:
			ircrypt_key_ex_memory[target].phase = 2
			weechat.command('','/mute -all notice -server %s %s >KEY-EX-NEXT-PHASE-2' \
					% (server, info['nick']))
			if not ircrypt_key_ex_memory[target].pub_key_send:
				ircrypt_public_key_send(server, args, info)
	else:
		weechat.command('','/mute -all notice -server %s %s >UCRY-PONG-WITHOUT-PING' \
				% (server, info['nick']))
	return ''


def ircrypt_receive_next_phase(server, args, info):
	'''This function handles incomming >KEY-EX-NEXT-PHASE- notices'''
	global ircrypt_gpg_id, ircrypt_key_ex_memory
	# Get prefix and number
	pre, number    = args.split('>KEY-EX-NEXT-PHASE-', 1)
	target = '%s/%s' % (server, info['nick'])

	try:
		number = int(number)
	except:
		weechat.command('','/mute -all notice -server %s %s >UCRY-WRONG-PHASE' \
				% (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	if ircrypt_key_ex_memory.get(target):
		if ircrypt_key_ex_memory[target].pub_key_send and ircrypt_key_ex_memory[target].pub_key_get and int(number) == 3:
			ircrypt_key_ex_memory[target].phase = 3
			ircrypt_sym_key_send(server, info['nick'])
		elif int(number) == 2:
			ircrypt_key_ex_memory[target].phase = 2
			if not ircrypt_key_ex_memory[target].pub_key_send:
				ircrypt_public_key_send(server, args, info)
		else:
			weechat.command('','/mute -all notice -server %s %s >UCRY-WRONG-PHASE' \
					% (server, info['nick']))
			try:
				del ircrypt_key_ex_memory[target]
			except KeyError:
				pass
	else:
		weechat.command('','/mute -all notice -server %s %s >UCRY-NEXT-PHASE-WITHOUT-PING' \
				% (server, info['nick']))
	return ''


def ircrypt_public_key_send(server, nick):
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
		msg = '>PUB-EX-%i %s' % (i, key[i*400:(i+1)*400])
		weechat.command('','/mute -all notice -server %s %s %s' % (server, nick, msg))
	return ''


def ircrypt_public_key_get(server, args, info):
	global ircrypt_pub_keys_memory, ircrypt_asym_id, ircrypt_key_ex_memory

	# Get prefix, number and message
	pre, message    = args.split('>PUB-EX-', 1)
	number, message = message.split(' ', 1)

	target = ('%s/%s' % (server, info['nick'])).lower()

	if not ircrypt_key_ex_memory.get(target):
		weechat.command('','/mute -all notice -server %s %s >UCRY-PUBLIC-KEY-EXCHANGE-WITHOUT-PING' % (server, info['nick']))
		return ''

	if not ircrypt_key_ex_memory[target].phase == 2:
		weechat.command('','/mute -all notice -server %s %s >UCRY-WRONG-PHASE-FOR-PUBLIC-KEY-EXCHANGE' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# Check if we got the last part of the message otherwise put the message
	# into a global memory and quit
	if int(number):
		if not target in ircrypt_pub_keys_memory:
			# - First element is list of requests
			# - Second element is currently received request
			ircrypt_pub_keys_memory[target] = MessageParts()
		# Add parts to current request
		ircrypt_pub_keys_memory[target].update(int(number), message)
		return ''
	else:
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
			ircrypt_pub_keys_memory[target].message))

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
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PUB-RECEIVED' % (server, info['nick']))
		return ''


def ircrypt_receive_key_ex_pub_received(server, args, info):
	global ircrypt_gpg_id, ircrypt_key_ex_memory

	target = '%s/%s' % (server, info['nick'])

	if ircrypt_key_ex_memory.get(target):
		if ircrypt_key_ex_memory[target].phase == 2:
			ircrypt_key_ex_memory[target].phase = 3
			ircrypt_sym_key_send(server, info['nick'])
		else:
			weechat.command('','/mute -all notice -server %s %s >UCRY-WRONG-PHASE' \
					% (server, info['nick']))
			try:
				del ircrypt_key_ex_memory[target]
			except KeyError:
				pass
	else:
		weechat.command('','/mute -all notice -server %s %s >UCRY-KEY-EX-PUB-RECEIVED-WITHOUT-PING' \
				% (server, info['nick']))
	return ''


def ircrypt_sym_key_send(server, nick):
	global ircrypt_asym_id, ircrypt_key_ex_memory, ircrypt_sym_keys_memory
	keypart = os.urandom(64)

	# Get key for the key memory
	target = '%s/%s' % (server, nick)

	p = subprocess.Popen([ircrypt_gpg_binary, '--homedir', ircrypt_gpg_homedir,
		'--batch', '--no-tty', '--quiet', '-s', '--trust-model', 'always', '-e',
		'-r', ircrypt_asym_id[target]], stdin=subprocess.PIPE,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(out, err) = p.communicate(keypart)
	if err:
		weechat.prnt('', err)

	ircrypt_key_ex_memory[target].update(keypart)
	if ircrypt_key_ex_memory[target].parts == 2:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-SYM-RECEIVED' % (server, nick))

	out = base64.b64encode(out)
	for i in range(1 + (len(out) / 400))[::-1]:
		msg = '>SYM-EX-%i %s' % (i, out[i*400:(i+1)*400])
		weechat.command('','/mute -all notice -server %s %s %s' % (server, nick, msg))


def ircrypt_sym_key_get(server, args, info):
	global ircrypt_pub_keys_memory, ircrypt_asym_id, ircrypt_key_ex_memory

	# Get prefix, number and message
	pre, message    = args.split('>SYM-EX-', 1)
	number, message = message.split(' ', 1)

	target = ('%s/%s' % (server, info['nick'])).lower()

	if not ircrypt_key_ex_memory.get(target):
		weechat.command('','/mute -all notice -server %s %s >UCRY-SYMMETRIC-KEY-EXCHANGE-WITHOUT-PING' % (server, info['nick']))
		return ''

	if not ircrypt_key_ex_memory[target].phase == 3:
		weechat.command('','/mute -all notice -server %s %s >UCRY-WRONG-PHASE-FOR-SYMMETRIC-KEY-EXCHANGE' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	catchword = (server, info['channel'], info['nick'])

	# Decrypt only if we got last part of the message
	# otherwise put the message into a global memory and quit
	if int(number) != 0:
		if not catchword in ircrypt_msg_memory:
			ircrypt_msg_memory[catchword] = MessageParts()
		ircrypt_msg_memory[catchword].update(int(number), message)
		return ''

	# Get whole message
	try:
		message = message + ircrypt_msg_memory[catchword].message
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
		return ''

	# Decrypt
	p = subprocess.Popen([ircrypt_gpg_binary, '--homedir', ircrypt_gpg_homedir,
		'--batch',  '--no-tty', '--quiet', '-d'], stdin=subprocess.PIPE,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	key, err = p.communicate(message)

	# Get and print GPG errors/warnings
	err = '\n'.join(['  ▼ ' + line for line in err.split('\n') if line])
	if p.returncode:
		weechat.prnt(buf, '%s%s%s' %
				(weechat.prefix('error'), weechat.color('red'), err))
		return args
	elif err:
		weechat.prnt(buf, '%s%s' % (weechat.color('gray'), err))

	# Remove old messages from memory
	try:
		del ircrypt_msg_memory[catchword]
	except KeyError:
		pass

	target = '%s/%s' % (server, info['nick'])

	ircrypt_key_ex_memory[target].update(key)
	if ircrypt_key_ex_memory[target].parts == 2:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-SYM-RECEIVED' % (server, info['nick']))
	return ''


def ircrypt_receive_key_ex_sym_received(server, args, info):
	global ircrypt_gpg_id, ircrypt_key_ex_memory

	target = '%s/%s' % (server, info['nick'])

	if ircrypt_key_ex_memory.get(target):
		if not ircrypt_key_ex_memory[target].phase == 3:
			weechat.command('','/mute -all notice -server %s %s >UCRY-WRONG-PHASE' \
					% (server, info['nick']))
			try:
				del ircrypt_key_ex_memory[target]
			except KeyError:
				pass
		elif not  ircrypt_key_ex_memory[target].parts == 2:
			weechat.command('','/mute -all notice -server %s %s >UCRY-NOT-ENOUGH-PARTS' \
					% (server, info['nick']))
			try:
				del ircrypt_key_ex_memory[target]
			except KeyError:
				pass
		else:
			weechat.command('','/ircrypt set-key -server %s %s %s' % (server, info['nick'],  base64.b64encode(ircrypt_key_ex_memory[target].sym_key)))
	else:
		weechat.command('','/mute -all notice -server %s %s >UCRY-KEY-EX-PUB-RECEIVED-WITHOUT-PING' \
				% (server, info['nick']))
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

	# If symmetric encryption return arguments
	return args


def ircrypt_decrypt_sym(server, args, info, key):
	'''This method is called to decrypt an symmetric encrypted messages and put
	them together again if necessary.

	:param server: IRC server the message comes from.
	:param args: IRC command line-
	:param info: dictionary created by info_get_hashtable
	:param key: key for decryption
	'''
	global ircrypt_msg_memory, ircrypt_config_option

	pre, message    = string.split(args, '>CRY-', 1)
	number, message = string.split(message, ' ', 1 )

	# Get key for the message memory
	catchword = '%s.%s.%s' % (server, info['channel'], info['nick'])

	# Decrypt only if we got last part of the message
	# otherwise put the message into a global memory and quit
	if int(number) != 0:
		if not catchword in ircrypt_msg_memory:
			ircrypt_msg_memory[catchword] = MessageParts()
		ircrypt_msg_memory[catchword].update(int(number), message)
		return ''

	# Get whole message
	try:
		message = message + ircrypt_msg_memory[catchword].message
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

	# Remove old messages from memory
	try:
		del ircrypt_msg_memory[catchword]
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
	global ircrypt_asym_id, ircrypt_key_ex_memory
	target = '%s/%s' % (server, nick)
	gpg_id = ircrypt_asym_id.get(target.lower())
	if gpg_id:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PING %s' \
				% (server, nick, gpg_id))
		ircrypt_key_ex_memory[target] = KeyExchange(True, False)
	else:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PING' \
				% (server, nick))
		ircrypt_key_ex_memory[target] = KeyExchange(False, False)
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

	if argv and not argv[0] in ['list', 'set-key', 'remove-key',
			'remove-public-key', 'set-cipher', 'remove-cipher', 'plain', 'query']:
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
		# If there is no text, just ignore the command
		if len(argv) < 2:
			return weechat.WEECHAT_RC_OK
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
		return ircrypt_receive_key_ex_ping(server, args, info)

	if '>KEY-EX-PONG' in args:
		return ircrypt_receive_key_ex_pong(server, args, info)

	if '>KEY-EX-NEXT-PHASE-' in args:
		return ircrypt_receive_next_phase(server, args, info)

	if '>KEY-EX-PUB-RECEIVED' in args:
		return ircrypt_receive_key_ex_pub_received(server, args, info)

	if '>SYM-EX-' in args:
		return ircrypt_sym_key_get(server, args, info)

	if '>KEY-EX-SYM-RECEIVED' in args:
		return  ircrypt_receive_key_ex_sym_received(server, args, info)

	if '>PUB-EX-' in args:
		return ircrypt_public_key_get(server, args, info)

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
	ircrypt_config_init()
	ircrypt_config_read()
	ircrypt_check_binary()
	if ircrypt_gpg_binary:
		weechat.hook_modifier('irc_in_privmsg',  'ircrypt_decrypt_hook', '')
		weechat.hook_modifier('irc_out_privmsg', 'ircrypt_encrypt_hook', '')
		weechat.hook_modifier('irc_in_notice',   'ircrypt_notice_hook', '')

		weechat.hook_command('ircrypt', 'Commands to manage IRCrypt options and execute IRCrypt commands',
				'[list]'
				'| set-key [-server <server>] <target> <key> '
				'| remove-key [-server <server>] <target> '
				'| remove-public-key [-server <server>] <nick> '
				'| set-cipher [-server <server>] <target> <cipher> '
				'| remove-cipher [-server <server>] <target> '
				'| query [-server <server>] <nick> '
				'| plain [-server <server>] [-channel <channel>] <message>',
				ircrypt_help_text,
				'list || set-key %(irc_channel)|%(nicks)|-server %(irc_servers) %- '
				'|| remove-key %(irc_channel)|%(nicks)|-server %(irc_servers) %- '
				'|| query %(nicks) -server %(irc_servers)'
				'|| remove-public-key %(nicks)|-server %(irc_servers) %- '
				'|| set-cipher %(irc_channel)|-server %(irc_servers) %- '
				'|| remove-cipher |%(irc_channel)|-server %(irc_servers) %- '
				'|| plain |-channel %(irc_channel)|-server %(irc_servers) %-',
				'ircrypt_command', '')
		ircrypt_init()
		weechat.bar_item_new('ircrypt', 'ircrypt_encryption_statusbar', '')
		weechat.hook_signal('ircrypt_buffer_opened', 'update_encryption_status', '')


def ircrypt_unload_script():
	'''Hook to ensure the configuration is properly written to disk when the
	script is unloaded.
	'''
	ircrypt_config_write()
	return weechat.WEECHAT_RC_OK
