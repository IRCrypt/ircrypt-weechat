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
# == Usage ==================================================================
#
#  The weechat IRCrypt plug-in will send messages encrypted to all channels for
#  which a passphrase is set. A channel can either be a regular IRC multi-user
#  channel (i.e. #IRCrypt) or another users nickname.
#
# To set, modify or remove a passphrase, use the /ircprypt command:
#
#   /ircrypt lkiesow secret                 # Sets the passphrase 'secret' to
#                                           # use for all communication with
#                                           # the user 'lkiesow' on the current
#                                           # server.
#   /ircrypt #IRCrypt xyz                   # Sets the passphrase 'xyz' to use
#                                           # for all communication within the
#                                           # channel '#IRCrypt' on the current
#                                           # server.
#   /ircrypt -server freenode shaardie abc  # Sets the passphrase 'abc' to use
#                                           # for all communication with the
#                                           # user 'shaardie' on the server
#                                           # 'freenode'.
#
#
# Configuration
#
# You can add 'ircrypt' to weechat.bar.status.items to have an indication that
# the message you are going to send is encrypted. If the marker for encrytion
# is set to {{cipher}} the global used chipher is added to the
# weechat.bar.status.items

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

import weechat, string, os, subprocess, base64
import time


# Global buffers used to store message parts, pending requests, configuration
# options, keys, etc.
ircrypt_msg_buffer = {}
ircrypt_config_file = None
ircrypt_config_section = {}
ircrypt_config_option = {}
ircrypt_keys = {}
ircrypt_asym_id = {}
ircrypt_cipher = {}
ircrypt_buffer = None
ircrypt_pending_requests = []
ircrypt_request_buffer = {}
ircrypt_pending_keys = []
ircrypt_keys_buffer = {}

# Constants used throughout this script
MAX_PART_LEN     = 300
MSG_PART_TIMEOUT = 300 # 5min
NEVER            = 0
ALWAYS           = 1
IF_NEW           = 2


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


def ircrypt_buffer_input_cb(data, buffer, args):
	'''input_callback
	This function called when input text is entered on ircrypt buffer

	:param data:
	:param buffer: The Irypt buffer
	:param args: the input test entered on ircrypt buffer
	'''

	global ircrypt_pending_requests, ircrypt_pending_keys

	# Split incomming text
	argv = args.split()

	# Command cancel
	if argv == ['cancel']:
		# Remove marker from all pending requests
		for req in filter(lambda x: x[3], ircrypt_pending_requests):
			req[3] = False
		# Remove marker from all pending keys
		for key in filter(lambda x: x[3], ircrypt_pending_keys):
			key[3] = False
		weechat.prnt(buffer, 'Canceled.')
		return weechat.WEECHAT_RC_OK

	# Command decline
	if argv == ['decline']:
		# Decline pending request
		for i in range(len(ircrypt_pending_requests)):
			if ircrypt_pending_requests[i][3]:
				# Get nick, channel and server
				nick    = ircrypt_pending_requests[i][1]
				channel = ircrypt_pending_requests[i][3]
				server  = ircrypt_pending_requests[i][0]
				# Send decline with servername and channel to nick with >UCRY-
				weechat.command('','/mute -all notice -server %s %s >UCRY-DECLINE %s %s ' \
						% (server, nick, server, channel))
				# Print message in ircrypt buffer, that request was declined
				weechat.prnt(buffer, 'Declined %s\'s request for channel %s (server %s).' % \
						(nick, channel, server))
				# Delete declined request
				del ircrypt_pending_requests[i]
				return weechat.WEECHAT_RC_OK

		# Decline pending keys
		for i in range(len(ircrypt_pending_keys)):
			if ircrypt_pending_keys[i][3]:
				# Get nick, channel and server
				nick    = ircrypt_pending_keys[i][1]
				channel = ircrypt_pending_keys[i][3][0]
				server  = ircrypt_pending_keys[i][0]
				# Print message in ircrypt buffer, that key was declined
				weechat.prnt(buffer, 'Declined %s\'s key for channel %s (server %s).' % \
						(nick, channel, server))
				# Delete declined key
				del ircrypt_pending_keys[i]
				return weechat.WEECHAT_RC_OK

		# Nothing to decline
		weechat.prnt(buffer, 'Nothing to decline.')
		return weechat.WEECHAT_RC_OK

	# Command accept
	if argv == ['accept']:
		# Accept pending request
		for i in range(len(ircrypt_pending_requests)):
			if ircrypt_pending_requests[i][3]:
				# Get nick, channel and server
				nick    = ircrypt_pending_requests[i][1]
				channel = ircrypt_pending_requests[i][3]
				server  = ircrypt_pending_requests[i][0]
				# Print message in ircrypt buffer, that requests was accepeted
				weechat.prnt(buffer, 'Accepted %s\'s request for channel %s (server %s).' % \
						(nick, channel, server))
				if ircrypt_keyex_sendkey(nick, channel, server) == weechat.WEECHAT_RC_OK:
					del ircrypt_pending_requests[i]
				return weechat.WEECHAT_RC_OK
		# Accept pending key
		for i in range(len(ircrypt_pending_keys)):
			if ircrypt_pending_keys[i][3]:
				# Get nick, channel, server and key
				nick    = ircrypt_pending_keys[i][1]
				channel = ircrypt_pending_keys[i][3][0]
				server  = ircrypt_pending_keys[i][0]
				key     = ' '.join(ircrypt_pending_keys[i][3][1:])
				# Print message in ircrypt buffer, that key was accepted
				weechat.prnt(buffer, 'Accepted %s\'s key for channel %s (server %s).' % \
						(nick, channel, server))
				# Set key for server/channel
				ircrypt_keys['%s/%s' % (server, channel)] = key
				del ircrypt_pending_keys[i]
				return weechat.WEECHAT_RC_OK

	return ircrypt_command(data, buffer, args)



def ircrypt_buffer_close_cb(data, buffer):
	'''close_callback
	This function called when ircrypt buffer is closed

	:param data:
	:param buffer: The Irypt buffer
	'''
	global ircrypt_buffer
	ircrypt_buffer = None
	return weechat.WEECHAT_RC_OK


def ircrypt_get_buffer(goto=NEVER):
	'''Function to create the IRCrypt buffer if non-existent. If the buffer
	alredy exists a pointer to the existing buffer is returned.

	:param goto:

	:returns: ircrypt buffer'''

	global ircrypt_buffer

	# if buffer exists, return buffer
	if ircrypt_buffer:
		if goto == ALWAYS:
			weechat.command('','/buffer IRCrypt')
		return ircrypt_buffer

	# create buffer
	ircrypt_buffer = weechat.buffer_new('IRCrypt', 'ircrypt_buffer_input_cb',
			'', 'ircrypt_buffer_close_cb', '')

	# set title
	weechat.buffer_set(ircrypt_buffer, 'title', 'IRCrypt Key Exchange')

	# disable logging, by setting local variable "no_log" to "1"
	weechat.buffer_set(ircrypt_buffer, 'localvar_set_no_log', '1')

	if goto != NEVER:
		weechat.command('','/buffer IRCrypt')

	return ircrypt_buffer


def ircrypt_keyex_askkey(nick, channel, servername):
	'''Part of key exchange
	This function is called when user starts key exchange

	:param nick: nick of which you want to have the key
	:param channel: channel for which the key is
	:param servername: name of the server
	'''

	global ircrypt_asym_id, ircrypt_config_option

	# Check if key exchange is enabled in the option
	if not weechat.config_boolean(
			weechat.config_get('ircrypt.cipher.exchange_enabled')):
		weechat.prnt(weechat.current_buffer(),
				'\n*** KEY EXCHANGE DISABLED ********************************************'
				'\n  For the moment, you have to explicitly Enable kex exchange with'
				'\n  “/set ircrypt.cipher.exchange_enabled on” if you want to use this'
				'\n  feature.'
				'\n  Be aware that at the moment, key exchange will not work without a'
				'\n  graphical window environment as GnuPG version 2.x will launch'
				'\n  pinentry so that your secret key is kept separate from Weechat at'
				'\n  any time. In a terminal environment, however, GnuPG would try to'
				'\n  start the ncurses interface instead which will cause ia conflict'
				'\n  with the weechat ncurses interface. This may lead to both user'
				'\n  interfaces becoming unusable.'
				'\n**********************************************************************')
		return weechat.WEECHAT_RC_OK

	# If no server was set, use the active one
	if not servername:
		servername = weechat.buffer_get_string(weechat.current_buffer(), 'localvar_server')

	# If no channel was set, assume that it is for a private conversation and
	# set it to the other persons nick.
	if not channel:
		channel = nick

	# Get asymetric identifier of nick
	key_id = ircrypt_asym_id.get('%s/%s' % (servername, nick))

	# Check if asymetric identifer exists
	if not key_id:
		weechat.prnt(weechat.current_buffer(), 'There is no ID for this Nick.')
		return weechat.WEECHAT_RC_OK

	# encrypt and sign channel with gpg2
	p = subprocess.Popen(['gpg2', '--sign', '--encrypt', '-r',
		key_id, '--batch', '--no-tty'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
		stderr=subprocess.PIPE)
	p.stdin.write(channel)
	p.stdin.close()
	encrypted = base64.b64encode(p.stdout.read())
	p.stdout.close()

	# Get and print GPG errors/warnings in ircrypt buffer
	err = p.stderr.read()
	p.stderr.close()
	if err:
		weechat.prnt(ircrypt_get_buffer(), err)
	if not encrypted:
		return weechat.WEECHAT_RC_ERROR

	# Send as notice in MAX_PART_LEN sized blocks
	for i in range(1 + (len(encrypted) / MAX_PART_LEN))[::-1]:
		msg = '>WCRY-%i %s' % (i, encrypted[i*MAX_PART_LEN:(i+1)*MAX_PART_LEN])
		weechat.command('','/mute -all notice -server %s %s %s' % (servername, nick, msg))

	# Print status message in ircrypt buffer
	weechat.prnt(ircrypt_get_buffer(IF_NEW),
			'Ask %s for key of channel %s/%s. Waiting for answer...' % \
			(nick, servername, channel))

	return weechat.WEECHAT_RC_OK


def ircrypt_keyex_get_request(servername, args, info):
	'''Part of key exchange
	This function is called when user gets key exchange request

	:param servername: name of the server
	:param args:
	:param info:
	'''
	global ircrypt_request_buffer, ircrypt_pending_requests

	# Get prefix, number and message
	pre, message    = args.split('>WCRY-', 1)
	number, message = message.split(' ', 1)

	# Get key for the request buffer
	buf_key = (servername, info['channel'], info['nick'])

	# Check if we got the last part of the message otherwise put the message
	# into a global buffer and quit
	if int(number):
		if not buf_key in ircrypt_request_buffer:
			# - First element is list of requests
			# - Second element is currently received request
			ircrypt_request_buffer[buf_key] = MessageParts()
		# Add parts to current request
		ircrypt_request_buffer[buf_key].update(int(number), message)
		return ''
	else:
		# We got the last part

		# if key exchange disabled send error notice
		if not weechat.config_boolean(
				weechat.config_get('ircrypt.cipher.exchange_enabled')):
			weechat.command('','/mute -all notice -server %s %s >UCRY-NOEXCHANGE' \
					% (servername, info['nick']))
			del ircrypt_request_buffer[buf_key]
			return ''

		# create a pending request
		ircrypt_pending_requests.append( [
			servername,
			info['nick'],
			message + ircrypt_request_buffer[buf_key].message,
			False
			] )
		del ircrypt_request_buffer[buf_key]

	# Print status message in ircrypt buffer
	weechat.prnt(ircrypt_get_buffer(), 'Received key request from nick %s/%s' %
			(servername, info['nick']))
	weechat.prnt(ircrypt_get_buffer(), 'Type verify requests [-server server] [nick] to'
			' verify the signature on this request(s).')
	# Return empty message
	return ''

def ircrypt_keyex_receive_key(servername, args, info):
	'''Part of key exchange
	This function is called when user receive a requested key

	:param servername: name of the server
	:param args:
	:param info:
	'''
	global ircrypt_keys_buffer, ircrypt_pending_keys

	# Get prefix, number and message
	pre, message    = args.split('>2CRY-', 1)
	number, message = message.split(' ', 1)

	# Get key for the request buffer
	buf_key = (servername, info['channel'], info['nick'])

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
		# We got the last part

		# if key exchange disabled ignore key
		if not weechat.config_boolean(
				weechat.config_get('ircrypt.cipher.exchange_enabled')):
			del ircrypt_keys_buffer[buf_key]
			return ''

		# create a pending key
		ircrypt_pending_keys.append( [
			servername,
			info['nick'],
			message + ircrypt_keys_buffer[buf_key].message,
			False
			] )
		del ircrypt_keys_buffer[buf_key]

	# Print status message in ircrypt buffer
	weechat.prnt(ircrypt_get_buffer(), 'Received key from nick %s/%s' %
			(servername, info['nick']))
	weechat.prnt(ircrypt_get_buffer(), 'Type verify keys [-server server] [nick] to'
			' verify the signature on this key(s).')
	# return empty message
	return ''


def ircrypt_keyex_sendkey(nick, channel, servername):
	'''Part of key exchange
	This function is called when user accepts key requests and sends the key back

	:param nick: nick of which you want to have the key
	:param channel: channel for which the key is
	:param servername: name of the server
	'''

	# If no server was set, use the active one
	if not servername:
		servername = weechat.buffer_get_string(weechat.current_buffer(), 'localvar_server')

	# If no channel was set, assume that it is for a private conversation and
	# set it to the other persons nick.
	if not channel:
		channel = nick

	# Get key and asymmetric identifier
	key = ircrypt_keys.get('%s/%s' % (servername, channel))
	key_id = ircrypt_asym_id.get('%s/%s' % (servername, nick))

	# Check if key exists
	if not key:
		weechat.prnt(weechat.current_buffer(), 'There is no key for this channel.')
		return weechat.WEECHAT_RC_OK

	# Check if asymetric identifer exists
	if not key_id:
		weechat.prnt(weechat.current_buffer(), 'There is no GPG ID for this Nick.')
		return weechat.WEECHAT_RC_OK

	# encrypt and sign channel and key with gpg2
	p = subprocess.Popen(['gpg2', '--sign', '--encrypt', '-r',
		key_id, '--batch', '--no-tty'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
		stderr=subprocess.PIPE)
	p.stdin.write('%s %s' % (channel, key))
	p.stdin.close()
	encrypted = base64.b64encode(p.stdout.read())
	p.stdout.close()

	# Get and print GPG errors/warnings in ircrypt buffer
	err = p.stderr.read()
	p.stderr.close()
	if err:
		weechat.prnt(ircrypt_get_buffer(), '%s' % err)
	p.wait()
	if p.returncode:
		weechat.prnt(ircrypt_get_buffer(), 'GnuPG reported error. Operation canceled')
	if not encrypted:
		return weechat.WEECHAT_RC_ERROR

	# Send as notice in 300 size blocks
	for i in range(1 + (len(encrypted) / 400))[::-1]:
		msg = '>2CRY-%i %s' % (i, encrypted[i*400:(i+1)*400])
		weechat.command('','/mute -all notice -server %s %s %s' % (servername, nick, msg))

	# Print status message in ircrypt buffer
	weechat.prnt(ircrypt_get_buffer(), 'Sent key for %s to %s/%s' % \
			(channel, servername, nick))

	return weechat.WEECHAT_RC_OK


def decrypt(data, msgtype, servername, args):
	'''Hook for incomming PRVMSG commands.
	This method will parse the input, check if it is an encrypted message and if
	it is, decrypt it.

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	'''
	global ircrypt_config_option, ircrypt_keys, ircrypt_asym_id

	info = weechat.info_get_hashtable('irc_message_parse', { 'message': args })

	# Check if asymmetric encrypted and if asymetric encryption is enabled
	if '>ACRY-' in args:
		if not weechat.config_boolean(
				weechat.config_get('ircrypt.cipher.asym_enabled')):
			weechat.command('','/notice %s >UCRY-CIPHER-NOT-FOUND' % info['nick'])
			return ''

		return decrypt_asym(servername, args, info)

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
	'''Hook for incomming PRVMSG commands.
	This method will parse the input, check if it is an encrypted message and if
	it is, decrypt it.

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
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
	p = subprocess.Popen(['gpg', '--batch',  '--no-tty', '--quiet',
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


def decrypt_asym(servername, args, info):
	'''Hook for incomming PRVMSG commands.
	This method will parse the input, check if it is an encrypted message and if
	it is, decrypt it.

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	'''
	global ircrypt_msg_buffer, ircrypt_config_option

	# Get prefix, number and message
	pre, message    = string.split(args, '>ACRY-', 1)
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
	p = subprocess.Popen(['gpg2', '--batch',  '--no-tty', '--quiet', '-d'],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
	This method will encrypt outgoing messages and if necessary (if they grow to
	large) split them into multiple parts.

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	'''
	global ircrypt_keys, ircrypt_asym_id
	info = weechat.info_get_hashtable("irc_message_parse", { "message": args })

	# check symmetric key
	key = ircrypt_keys.get('%s/%s' % (servername, info['channel']))
	if key:
		return encrypt_sym(servername, args, info, key)

	# check asymmetric key id
	key_id = ircrypt_asym_id.get('%s/%s' % (servername, info['channel']))
	if key_id and weechat.config_boolean(
				weechat.config_get('ircrypt.cipher.asym_enabled')):
		return encrypt_asym(servername, args, info, key_id)

	# No key -> don't encrypt
	return args


def encrypt_sym(servername, args, info, key):
	'''Hook for outgoing PRVMSG commands.
	This method will encrypt outgoing messages and if necessary (if they grow to
	large) split them into multiple parts.

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	'''

	global ircrypt_cipher

	# Get cipher
	cipher = ircrypt_cipher.get('%s/%s' % (servername, info['channel']),
			weechat.config_string(ircrypt_config_option['sym_cipher']))
	# Get prefix and message
	pre, message = string.split(args, ':', 1)

	# encrypt message
	p = subprocess.Popen(['gpg', '--batch',  '--no-tty', '--quiet',
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



def encrypt_asym(servername, args, info, key_id):
	'''Hook for outgoing PRVMSG commands.
	This method will encrypt outgoing messages and if necessary (if they grow to
	large) split them into multiple parts.

	:param data:
	:param msgtype:
	:param servername: IRC server the message comes from.
	:param args: IRC command line-
	'''

	# Get prefix and message
	pre, message = string.split(args, ':', 1)

	# Encrypt message
	p = subprocess.Popen(['gpg', '--batch',  '--no-tty', '--quiet', '-e', '-r',
		key_id], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
		stderr=subprocess.PIPE)
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

def ircrypt_config_asym_id_read_cb(data, config_file, section_name, option_name,
		value):
	'''Read elements of the key section from the configuration file.
	'''
	global ircrypt_asym_id

	if not weechat.config_new_option(config_file, section_name, option_name,
			'string', 'asym_id', '', 0, 0, '', value, 0, '', '', '', '', '', ''):
		return weechat.WEECHAT_CONFIG_OPTION_SET_ERROR

	ircrypt_asym_id[option_name] = value
	return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED


def ircrypt_config_asym_id_write_cb(data, config_file, section_name):
	'''Write passphrases to the key section of the configuration file.
	'''
	global ircrypt_asym_id

	weechat.config_write_line(config_file, section_name, '')
	for target, asym_id in sorted(ircrypt_asym_id.iteritems()):
		weechat.config_write_line(config_file, target, asym_id)

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

	global ircrypt_keys, ircrypt_asym_id, ircrypt_cipher

	# Get buffer
	buffer = weechat.current_buffer()
	# Print keys, asymmetric identifier and special cipher in current buffer
	weechat.prnt(buffer,'\nKeys:')
	for servchan,key in ircrypt_keys.iteritems():
		weechat.prnt(buffer,'%s : %s' % (servchan, key))

	weechat.prnt(buffer,'\nAsymmetric identifier:')
	for servchan,ids in ircrypt_asym_id.iteritems():
		weechat.prnt(buffer,'%s : %s' % (servchan, ids))

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


def ircrypt_command_set_pub(target, pub):
	'''ircrypt command to set asymmetric identifier for target (target is a server/channel combination)'''
	global ircrypt_asym_id
	# Set asymmetric identifier
	ircrypt_asym_id[target] = pub
	# Print status message in current buffer
	weechat.prnt(weechat.current_buffer(), 'Set asymmetric identifier for %s' % target)
	return weechat.WEECHAT_RC_OK


def ircrypt_command_remove_pub(target):
	'''ircrypt command to remove asymmetric identifier for target (target is a server/channel combination)'''
	global ircrypt_asym_id
	# Get buffer
	buffer = weechat.current_buffer()
	# Check if asymmetric identifier is set and print error in current buffer otherwise
	if target not in ircrypt_asym_id:
		weechat.prnt(buffer, 'No existing asymmetric identifier for %s.' % target)
		return weechat.WEECHAT_RC_OK
	# Delete asymmetric identifier and print status message in current buffer
	del ircrypt_asym_id[target]
	weechat.prnt(buffer, 'Removed asymmetric identifier for %s' % target)
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

def ircrypt_command_verify_requests(server, nick):
	'''This function is called when user want to verify their requests

	:param server: name of the server
	:param nick: nick of which you want to verify the requests
	'''
	global ircrypt_pending_requests, ircrypt_pending_keys

	# Get pending requests, pending keys and ircrypt buffer
	requests = ircrypt_pending_requests
	keys = ircrypt_pending_keys
	buffer = ircrypt_get_buffer(ALWAYS)

	# Remove marker from all pending requests
	for req in filter(lambda x: x[3], requests):
		req[3] = False

	# Remove marker from all pending keys
	for key in filter(lambda x: x[3], keys):
		key[3] = False

	# Prefilter requests
	if (server and nick):
		requests = filter(lambda x: x[0] == server and x[1] == nick,
				ircrypt_pending_requests)

	# Run through prefilterd requests
	for req in requests:
		server = req[0]
		nick   = req[1]
		# Decrypt and show signature
		p = subprocess.Popen(['gpg2', '--batch',  '--no-tty', '--quiet',
			'-d'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
		p.stdin.write(base64.b64decode(req[2]))
		p.stdin.close()
		channel = p.stdout.read()
		p.stdout.close()

		# if channel is own nick, change channel to the nick of the sender
		if channel == weechat.info_get('irc_nick',server):
			channel = nick

		# Mark request
		req[3] = channel

		# Get and print GPG errors/warnings
		err = p.stderr.read()
		p.stderr.close()
		weechat.prnt(buffer, '%s requested key for channel %s (server %s)' % \
				(nick, channel, server))
		# We need a test of signature
		weechat.prnt(buffer, '%s' % err)
		weechat.prnt(buffer, 'What do you want to do? [accept | decline | cancel]')
		return weechat.WEECHAT_RC_OK

	# No matching request
	return weechat.WEECHAT_RC_OK


def ircrypt_command_verify_keys(server, nick):
	'''This function is called when user want to verify their received keys

	:param server: name of the server
	:param nick: nick of which you want to verify the received key
	'''
	global ircrypt_pending_requests, ircrypt_pending_keys
	# Get pending requests, pending keys and the ircrypt buffer
	requests = ircrypt_pending_requests
	keys = ircrypt_pending_keys
	buffer = ircrypt_get_buffer(ALWAYS)

	# Remove marker from all pending requests
	for req in filter(lambda x: x[3], requests):
		req[3] = False

	# Remove marker from all pending keys
	for key in filter(lambda x: x[3], keys):
		key[3] = False

	# Prefilter keys
	if (server and nick):
		keys = filter(lambda x: x[0] == server and x[1] == nick,
				ircrypt_pending_keys)

	# Run through prefilterd keys
	for key in keys:
		server = key[0]
		nick   = key[1]
		# Decrypt and show signature
		p = subprocess.Popen(['gpg2', '--batch',  '--no-tty', '--quiet',
			'-d'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
		p.stdin.write(base64.b64decode(key[2]))
		p.stdin.close()
		[channel, channel_key] = p.stdout.read().split(' ', 1)
		p.stdout.close()

		# if channel is own nick, change channel to the nick of the sender
		if channel == weechat.info_get('irc_nick',server):
			channel = nick

		# Mark request
		key[3] = [channel, channel_key]

		# Get and print GPG errors/warnings
		err = p.stderr.read()
		p.stderr.close()
		weechat.prnt(buffer, '%s send you the key for channel %s (server %s)' % \
				(nick, channel, server))
		# We need a test of signature
		weechat.prnt(buffer, '%s' % err)
		weechat.prnt(buffer, 'What do you want to do? [accept | decline | cancel]')
		return weechat.WEECHAT_RC_OK

	# No matching keys
	return weechat.WEECHAT_RC_OK


def ircrypt_command(data, buffer, args):
	'''Hook to handle the /ircrypt weechat command. This method is also used for
	all commands typed into the IRCrypt buffer.
	'''
	global ircrypt_keys, ircrypt_asym_id, ircrypt_cipher

	# list
	if args == '' or args == 'list':
		return ircrypt_command_list()

	# buffer, create ircrypt buffer
	if args == 'buffer':
		ircrypt_get_buffer()
		return weechat.WEECHAT_RC_OK

	argv = [a for a in args.split(' ') if a]

	# verify
	if argv[0] == 'verify':
		if len(argv) > 1:
			if argv[1] == 'requests':
				if len(argv) == 4:
					return ircrypt_command_verify_requests(argv[2], argv[3])
				return ircrypt_command_verify_requests('', '')
			if argv[1] == 'keys':
				if len(argv) == 4:
					return ircrypt_command_verify_keys(argv[2], argv[3])
				return ircrypt_command_verify_keys('', '')

	# Check if a server was set
	if (len(argv) > 2 and argv[1] == '-server'):
		server_name = argv[2]
		del argv[2]
		del argv[1]
		args = args.split(' ', 2)[-1]
	else:
		# Try to determine the server automatically
		server_name = weechat.buffer_get_string(buffer, 'localvar_server')
		if not server_name:
			# if no server was set print message in ircrypt buffer and throw error
			weechat.prnt(buffer, 'Unknown Server. Please use -server to specify server')
			return weechat.WEECHAT_RC_ERROR

	# We need at least one additional argument
	if len(argv) < 2:
		return weechat.WEECHAT_RC_ERROR

	target = '%s/%s' % (server_name, argv[1])

	# Ask for a key
	if argv[0] == 'exchange':
		if len(argv) == 2:
			return ircrypt_keyex_askkey(argv[1], None, server_name)
		if len(argv) == 3:
			return ircrypt_keyex_askkey(argv[1], argv[2], server_name)
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

	# Set asymmetric ids
	if argv[0] == 'set-gpg-id':
		if len(argv) < 3:
			return weechat.WEECHAT_RC_ERROR
		return ircrypt_command_set_pub(target, ' '.join(argv[2:]))

	# Remove asymmetric ids
	if argv[0] == 'remove-gpg-id':
		if len(argv) != 2:
			return weechat.WEECHAT_RC_ERROR
		return ircrypt_command_remove_pub(target)

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
		return ircrypt_keyex_get_request(servername, args, info)

	if '>2CRY-' in args:
		return ircrypt_keyex_receive_key(servername, args, info)

	return args


# register plugin
if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
		SCRIPT_DESC, 'ircrypt_unload_script', 'UTF-8'):
	# register the modifiers
	weechat.hook_modifier('irc_in_privmsg',  'decrypt', '')
	weechat.hook_modifier('irc_out_privmsg', 'encrypt', '')
	weechat.hook_modifier('irc_in_notice',   'ircrypt_notice_hook', '')

	weechat.hook_command('ircrypt', 'Manage IRCrypt Keys and public key identifier',
			'[list] '
			'| [buffer] '
			'| [verify] [server] [nick]'
			'| exchange [-server <server>] <nick> [channel] '
			'| set-key [-server <server>] <target> <key> '
			'| remove-key [-server <server>] <target>'
			'| set-gpg-id [-server <server>] <nick> <id>'
			'| remove-gpg-id [-server <server>] <nick>'
			'| set-cipher [-server <server>] <channel> <cipher>'
			'| remove-cipher [-server <server>] <channel>',
			'Add, change or remove key for nick or channel.\n'
			'Add, change or remove public key identifier for nick.\n'
			'Add, change or remove special cipher for nick or channel.\n\n'
			'Examples:\n'
			'Set the key for a channel:'
			'\n   /ircrypt set-key -server freenet #IRCrypt key\n'
			'Remove the key:'
			'\n   /ircrypt remove-key #IRCrypt\n'
			'Set the key for a user:'
			'\n   /ircrypt set-key nick key\n'
			'Set the public key identifier for a user:'
			'\n   /ircrypt set-gpg-id -server freenode nick Id\n'
			'Remove public key identifier for a user:'
			'\n   /ircrypt remove-gpg-id nick\n'
			'Switch to a specific cipher for a channel:'
			'\n   /ircrypt set-cipher -server freenode #IRCrypt TWOFISH'
			'Unset the specific cipher for a channel:'
			'\n   /ircrypt remove-cipher #IRCrypt',
			'list || buffer || set-key %(irc_channel)|%(nicks)|-server %(irc_servers) %- '
			'|| remove-key %(irc_channel)|%(nicks)|-server %(irc_servers) %- '
			'|| exchange %(nicks) %(irc_channel) -server %(irc_servers)'
			'|| verify requests|keys %(irc_servers) %(nicks)'
			'|| set-gpg-id %(nicks)|-server %(irc_servers) %- '
			'|| remove-gpg-id |%(nicks)|-server %(irc_servers) %-'
			'|| set-cipher %(irc_channel)|-server %(irc_servers) %- '
			'|| remove-cipher |%(irc_channel)|-server %(irc_servers) %-',
			'ircrypt_command', '')

	ircrypt_config_init()
	ircrypt_config_read()
	weechat.bar_item_new('ircrypt', 'ircrypt_encryption_statusbar', '')
	weechat.hook_signal('ircrypt_buffer_opened', 'update_encryption_status', '')


def ircrypt_unload_script():
	'''Hook to ensure the configuration is properly written to disk when the
	script is unloaded.
	'''
	ircrypt_config_write()
	return weechat.WEECHAT_RC_OK
