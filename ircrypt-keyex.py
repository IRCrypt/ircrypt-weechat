# -*- coding: utf-8 -*-
#
# IRCrypt: Addon for IRCrypt to enable key exchange via public key authentication
# ===============================================================================
#
# Copyright (C) 2013-2014
#    Lars Kiesow   <lkiesow@uos.de>
#    Sven Haardiek <sven@haardiek.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
#
#
# == About ======================================================================

#  The weechat IRCrypt-KeyEx plug-in is an addon for the weechat IRCrypt
#  plug-in to enable key exchange via public key exchange. The plug-in will
#  create a RSA keypair and use this to do plublic key authentication with
#  other users and to exchange symmetric keys.
#
# == Project ====================================================================
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


import weechat, string, os, subprocess, base64, time, imp
ircrypt = None

# Constants used in this script
SCRIPT_NAME    = 'ircrypt-keyex'
SCRIPT_AUTHOR  = 'Sven Haardiek <sven@haardiek.de>, Lars Kiesow <lkiesow@uos.de>'
SCRIPT_VERSION = 'SNAPSHOT'
SCRIPT_LICENSE = 'GLP3'
SCRIPT_DESC    = 'IRCrypt-KeyEx: Addon for IRCrypt to enable key exchange via public key authentication'
SCRIPT_HELP_TEXT = '''%(bold)sIRCrypt-KeyEx command options: %(normal)s
list                                                    List public key fingerprints
start              [-server <server>] <nick>            Start key exchange with nick
remove-public-key  [-server <server>] <nick>            Remove public key id for nick

%(bold)sExamples: %(normal)s
Start key exchange with a user
   /ircrypt-keyex start nick
Remove public key identifier for a user:
   /ircrypt-keyex remove-public-key nick

%(bold)sConfiguration: %(normal)s
Tip: You can list all options and what they are currently set to by executing:
   /set ircrypt-keyex.*
%(bold)sircrypt-keyex.general.binary %(normal)s
   This will set the GnuPG binary used for encryption and decryption. IRCrypt-keyex
   will try to set this automatically.
''' % {'bold':weechat.color('bold'), 'normal':weechat.color('-bold')}

MAX_PART_LEN     = 300
MSG_PART_TIMEOUT = 300 # 5min


# Global variables and memory used to store message parts, pending requests,
# configuration options, keys, etc.
ircrypt_sym_key_memory   = {}
ircrypt_config_file      = None
ircrypt_config_section   = {}
ircrypt_config_option    = {}
ircrypt_asym_id          = {}
ircrypt_pub_keys_memory  = {}
ircrypt_key_ex_memory    = {}
ircrypt_gpg_binary       = None
ircrypt_gpg_homedir      = None
ircrypt_gpg_id           = None


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


class KeyExchange:
	'''Class used for key exchange

	@pub_key_receive indicates wether the public key has not yet received
	@pub_key_send indicates wether the public key has not yet been send
	@parts specify the number of keyparts
	@sym_key is the symmetric key
	@sym_received incicates wether the symmetric key is completed
	'''

	pub_key_receive = False
	pub_key_send = False
	parts = 0
	sym_key  = ''
	sym_received = False

	def __init__(self, pub_key_receive, pub_key_send):
		'''This function initialize the instance'''
		self.pub_key_receive = pub_key_receive
		self.pub_key_send = pub_key_send

	def update(self, keypart):
		'''This function update the symmetric key and do the XOR operation'''
		if self.sym_key == '':
			self.sym_key = keypart
		else:
			self.sym_key = ''.join(chr(ord(x) ^ ord(y)) for x, y in
					zip(self.sym_key, keypart))

		self.parts = self.parts + 1


def ircrypt_gnupg(stdin, *args):
	'''Try to execute gpg with given input and options.

	:param stdin: Input for GnuPG
	:param  args: Additional command line options for GnuPG
	:returns:     Tuple containing returncode, stdout and stderr
	'''
	p = subprocess.Popen(
			[ircrypt_gpg_binary, '--batch',  '--no-tty'] + list(args),
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate(stdin)
	return (p.returncode, out, err)


def ircrypt_split_msg(cmd, pre, msg):
	'''Convert encrypted message in MAX_PART_LEN sized blocks
	'''
	return '\n'.join(['%s:>%s-%i %s' % (cmd, pre, i,
		msg[i*MAX_PART_LEN:(i+1) * MAX_PART_LEN])
		for i in xrange(1 + (len(msg) / MAX_PART_LEN))][::-1])


def ircrypt_error(msg, buf):
	'''Print errors to a given buffer. Errors are printed in red and have the
	weechat error prefix.
	'''
	weechat.prnt(buf, weechat.prefix('error') + weechat.color('red') + msg)


def ircrypt_warn(msg, buf=''):
	'''Print warnings. If no buffer is set, the default weechat buffer is used.
	Warnin are printed in gray without marker.
	'''
	weechat.prnt(buf, weechat.color('gray') + msg)


def ircrypt_info(msg, buf=None):
	'''Print ifo message to specified buffer. If no buffer is set, the current
	foreground buffer is used to print the message.
	'''
	if buf is None:
		buf = weechat.current_buffer()
	weechat.prnt(buf, msg)


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
			ircrypt_error('Automatic detection of the GnuPG binary failed and '
					'nothing is set manually. You wont be able to use IRCrypt like '
					'this. Please install GnuPG or set the path to the binary to '
					'use.', '')
		else:
			ircrypt_info('Found %s' % version, '')
			weechat.config_option_set(ircrypt_config_option['binary'], ircrypt_gpg_binary, 1)


def ircrypt_gnupg_init():
	'''Initialize GnuPG'''
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
	(ret, out, err) = ircrypt_gnupg('', '--homedir', ircrypt_gpg_homedir,
			'--list-secret-keys', '--with-fingerprint', '--with-colon')

	# GnuPG returncode
	if ret:
		ircrypt_error(err, weechat.current_buffer())
		return weechat.WEECHAT_RC_ERROR
	elif err:
		ircrypt_warn(err, '')

	# There is a secret key
	if out:
		try:
			ircrypt_gpg_id = out.split('fpr')[-1].split('\n')[0].strip(':')
			ircrypt_info('Found private gpg key with fingerprint %s' %
					ircrypt_gpg_id, '')
			return weechat.WEECHAT_RC_OK
		except:
			ircrypt_error('Unable to get key id', '')

	# Try to generate a key
	ircrypt_warn('No private key for assymetric encryption was found in the '
			+ 'IRCrypt GPG keyring. IRCrypt will now try to automatically generate a '
			+ 'new key. This might take quite some time as this procedure depends on '
			+ 'the gathering of enough entropy for generating cryptographically '
			+ 'strong random numbers. You cannot use the key exchange (public key'
			+ 'authentication) until this process is done. However, it does not'
			+ 'affect the symmetric encryption which can already be used. You '
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
	'''Callback for process hook to generate key'''

	# Error
	if errorcode:
		ircrypt_error(err, '')
		return weechat.WEECHAT_RC_ERROR
	elif err:
		ircrypt_warn(err)

	ircrypt_info('A private key for asymmetric encryption was successfully'
			+ 'generated and can now be used for communication.')
	return ircrypt_gnupg_init()


def ircrypt_receive_key_ex_ping(server, args, info):
	'''This function handles incomming >KEY-EX-PING notices'''
	global ircrypt_gpg_id, ircrypt_key_ex_memory

	# Check for ircrypt plugin
	if not ircrypt_check_ircrypt:
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		return ''

	# Check if own gpg key exists
	if not ircrypt_gpg_id:
		ircrypt_error('Error in IRCrypt key exchange', weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		return ''

	# Get fingerprint from message
	try:
		fingerprint = args.split('>KEY-EX-PING')[-1].split(' (')[0].lstrip(' ')
	except:
		ircrypt_error('Error in IRCrypt key exchange', weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		return ''

	# Wrong fingerprint: Error
	if fingerprint and fingerprint != ircrypt_gpg_id:
		ircrypt_error('%s tries key exchange with wrong fingerprint' \
				% info['nick'], weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-PING-WITH-INVALID-FINGERPRINT' % (server, info['nick']))
		return ''

	# Send back a >KEY-EX-PONG with optional fingerprint and create an instance
	# of the class KeyExchange
	target = '%s/%s' % (server, info['nick'])
	gpg_id = ircrypt_asym_id.get(target.lower())
	if gpg_id:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PONG %s' \
				% (server, info['nick'], gpg_id))
		if fingerprint:
			ircrypt_key_ex_memory[target] = KeyExchange(False, False)
		else:
			ircrypt_key_ex_memory[target] = KeyExchange(False, True)
	else:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PONG' \
				% (server, info['nick']))
		if fingerprint:
			ircrypt_key_ex_memory[target] = KeyExchange(True, False)
		else:
			ircrypt_key_ex_memory[target] = KeyExchange(True, True)

	return ''


def ircrypt_receive_key_ex_pong(server, args, info):
	'''This function handles incomming >KEY-EX-PONG notices'''
	global ircrypt_gpg_id, ircrypt_key_ex_memory

	target = '%s/%s' % (server, info['nick'])

	# No instance of KeyExchange: Error
	if not ircrypt_key_ex_memory.get(target):
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-NO-KEY-EXCHANGE' % (server, info['nick']))
		return ''

	fingerprint = args.split('>KEY-EX-PONG')[-1].lstrip(' ')

	# Wrong fingerprint: Error and try to delete instance of KeyExchange
	if fingerprint and fingerprint != ircrypt_gpg_id:
		ircrypt_error('%s tries key exchange with wrong fingerprint' \
				% info['nick'], weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-PING-WITH-INVALID-FINGERPRINT' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# If correct fingerprint, the public key must not been sent
	if fingerprint:
		ircrypt_key_ex_memory[target].pub_key_send = False

	# Notice to start next phase
	weechat.command('','/mute -all notice -server %s %s >KEY-EX-NEXT-PHASE' \
			% (server, info['nick']))

	# If no public key must be sent, start symmetric key exchange. Otherwise
	# send public key, if necessary
	if (ircrypt_key_ex_memory[target].pub_key_send,
			ircrypt_key_ex_memory[target].pub_key_receive) == (False, False):
		ircrypt_sym_key_send(server, info['nick'])
	elif ircrypt_key_ex_memory[target].pub_key_send:
		ircrypt_public_key_send(server, info['nick'])

	return ''


def ircrypt_receive_next_phase(server, args, info):
	'''This function handles incomming >KEY-EX-NEXT-PHASE notices'''
	global ircrypt_gpg_id, ircrypt_key_ex_memory

	target = '%s/%s' % (server, info['nick'])

	# No instance of KeyExchange: Error
	if not ircrypt_key_ex_memory.get(target):
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-NO-KEY-EXCHANGE' % (server, info['nick']))
		return ''

	# If no public key must be sent, start symmetric key exchange. Otherwise
	# send public key, if necessary
	if (ircrypt_key_ex_memory[target].pub_key_send,
			ircrypt_key_ex_memory[target].pub_key_receive) == (False,False):
		ircrypt_sym_key_send(server, info['nick'])
	elif ircrypt_key_ex_memory[target].pub_key_send:
		ircrypt_public_key_send(server, info['nick'])

	return ''


def ircrypt_public_key_send(server, nick):
	'''This function sends away own public key'''
	global ircrypt_gpg_homedir, ircrypt_gpg_id, ircrypt_key_ex_memory

	# Export own public key and b64encode the public key. Print error if
	# necessary.
	if not ircrypt_gpg_id:
		ircrypt_error('Error in IRCrypt key exchange', weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		return ''

	(ret, out, err) = ircrypt_gnupg('', '--homedir', ircrypt_gpg_homedir,
			'--export', ircrypt_gpg_id)

	if ret:
		ircrypt_error(err, weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''
	elif err:
		ircrypt_warn(err)

	pub_key = base64.b64encode(out)

	# Partition the public key and send it away
	for i in range(1 + (len(pub_key) / MAX_PART_LEN))[::-1]:
		msg = '>PUB-EX-%i %s' % (i, pub_key[i*MAX_PART_LEN:(i+1)*MAX_PART_LEN])
		weechat.command('','/mute -all notice -server %s %s %s' % (server, nick, msg))

	return ''


def ircrypt_public_key_get(server, args, info):
	'''This function handles incomming >PUB-EX- messages'''
	global ircrypt_pub_keys_memory, ircrypt_asym_id, ircrypt_key_ex_memory

	# Get prefix, number and message
	pre, message    = args.split('>PUB-EX-', 1)
	number, message = message.split(' ', 1)

	target = ('%s/%s' % (server, info['nick'])).lower()

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

	# No instance of KeyExchange: Error
	if not ircrypt_key_ex_memory.get(target):
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-NO-KEY-EXCHANGE' % (server, info['nick']))
		return ''

	# If no request for a public key: Error and try to delete instance of
	# KeyExchange
	if not ircrypt_key_ex_memory[target].pub_key_receive:
		ircrypt_error('%s sends his public key without inquiry' % info['nick'],
				weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-NO-REQUEST-FOR-PUBLIC-KEY' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# If there is a public identifier: Error and try to delete instance of
	# KeyExchange
	key_id = ircrypt_asym_id.get(target)
	if key_id:
		ircrypt_error('Error in IRCrypt key exchange', weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# Get whole message
	try:
		message = message + ircrypt_pub_keys_memory[target].message
		del ircrypt_pub_keys_memory[target]
	except KeyError:
		pass

	# Decode base64 encoded message
	try:
		message = base64.b64decode(message)
	except:
		ircrypt_error('Error in IRCrypt key exchange', weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# Import public key
	(ret, out, err) = ircrypt_gnupg(message, '--homedir', ircrypt_gpg_homedir,
			'--keyid-format', '0xlong', '--import')

	# Print error (There are the information about the imported public key)
	# and quit key exchange if necessary
	if ret:
		ircrypt_error(err, weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''
	elif err:
		ircrypt_warn(err)

        weechat.prnt('', out)

	# Try to get public key identifier.
	try:
		gpg_id = err.split('0x',1)[1].split(':',1)[0]
	except:
		ircrypt_error('Error in IRCrypt key exchange', weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# Probe for GPG fingerprint
	(ret, out, err) = ircrypt_gnupg('', '--homedir', ircrypt_gpg_homedir,
			'--fingerprint', '--with-colon')

	# Print error (There are the information about the imported public key)
	# and quit key exchange if necessary
	if ret:
		ircrypt_error(err, weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''
	elif err:
		ircrypt_warn(err)

	# There is a secret key
	try:
		out = [ line for line in out.split('\n') \
				if (gpg_id + ':') in line and line.startswith('fpr:') ][-1]
		gpg_id = out.split('fpr')[-1].strip(':')
	except:
		ircrypt_error('Error in IRCrypt key exchange', weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# Set asymmetric identifier and remember that the public key was received
	ircrypt_asym_id[target.lower()] = gpg_id
	ircrypt_key_ex_memory[target].pub_key_receive = False

	# Send status back
	weechat.command('','/mute -all notice -server %s %s '
			'>KEY-EX-PUB-RECEIVED' % (server, info['nick']))

	# Start symmetic key exchange if public key exchange is closed
	if (ircrypt_key_ex_memory[target].pub_key_send,
			ircrypt_key_ex_memory[target].pub_key_receive) == (False,False):
		ircrypt_sym_key_send(server, info['nick'])

	return ''


def ircrypt_receive_key_ex_pub_received(server, args, info):
	'''This function handles incomming >PUB-KEY-RECEIVED notices'''
	global ircrypt_gpg_id, ircrypt_key_ex_memory

	target = '%s/%s' % (server, info['nick'])

	# No instance of KeyExchange: Error
	if not ircrypt_key_ex_memory.get(target):
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-NO-KEY-EXCHANGE' % (server, info['nick']))
		return ''

	# Set asymmetric identifier and remember that the public key was sent
	ircrypt_key_ex_memory[target].pub_key_send = False

	# Start symmetic key exchange if public key exchange is closed
	if (ircrypt_key_ex_memory[target].pub_key_send,
			ircrypt_key_ex_memory[target].pub_key_receive) == (False,False):
		ircrypt_sym_key_send(server, info['nick'])

	return ''


def ircrypt_sym_key_send(server, nick):
	'''This function create a part of a symmetric key and send it away'''
	global ircrypt_asym_id, ircrypt_key_ex_memory, ircrypt_sym_keys_memory

	# Create part of key
	keypart = os.urandom(64)

	target = '%s/%s' % (server, nick)

	(ret, out, err) = ircrypt_gnupg(keypart, '--homedir', ircrypt_gpg_homedir,
			'-s', '--trust-model', 'always', '-e', '-r', ircrypt_asym_id[target])

	# Print error and quit key exchange if necessary
	if ret:
		ircrypt_error(err, weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''
	elif err:
		ircrypt_warn(err)

	# Update symmetric key
	ircrypt_key_ex_memory[target].update(keypart)

	# If symmetric key is complete, send status back
	if ircrypt_key_ex_memory[target].parts == 2:
		weechat.command('','/mute -all notice -server %s %s '
				'>KEY-EX-SYM-RECEIVED' % (server, nick))
		# If the symmetric key is also complete by the counterpart set symmetric
		# key
		if ircrypt_key_ex_memory[target].sym_received:
			weechat.command('','/ircrypt set-key -server %s %s %s' \
					% (server, info['nick'],
						base64.b64encode(ircrypt_key_ex_memory[target].sym_key)))

	# Print encrypted part of the symmetric key in multiple notices
	out = base64.b64encode(out)
	for i in range(1 + (len(out) / MAX_PART_LEN))[::-1]:
		msg = '>SYM-EX-%i %s' % (i, out[i*MAX_PART_LEN:(i+1)*MAX_PART_LEN])
		weechat.command('','/mute -all notice -server %s %s %s' % (server, nick, msg))


def ircrypt_sym_key_get(server, args, info):
	global ircrypt_pub_keys_memory, ircrypt_asym_id, ircrypt_key_ex_memory

	# Get prefix, number and message
	pre, message    = args.split('>SYM-EX-', 1)
	number, message = message.split(' ', 1)

	catchword = (server, info['channel'], info['nick'])

	# Decrypt only if we got last part of the message
	# otherwise put the message into a global memory and quit
	if int(number) != 0:
		if not catchword in ircrypt_sym_key_memory:
			ircrypt_sym_key_memory[catchword] = MessageParts()
		ircrypt_sym_key_memory[catchword].update(int(number), message)
		return ''

	# Get whole message
	try:
		message = message + ircrypt_sym_key_memory[catchword].message
	except KeyError:
		pass

	target = ('%s/%s' % (server, info['nick'])).lower()

	# No instance of KeyExchange: Error
	if not ircrypt_key_ex_memory.get(target):
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-NO-KEY-EXCHANGE' % (server, info['nick']))
		return ''

	# No request for symmtric key exchange: Error and try to delete instance
	if (ircrypt_key_ex_memory[target].pub_key_send or
			ircrypt_key_ex_memory[target].pub_key_receive):
		ircrypt_error('%s sends symmetric key without inquiry' % info['nick'],
				weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-NO-REQUEST-FOR-SYMMETRIC-KEY' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# Decode base64 encoded message
	try:
		message = base64.b64decode(message)
	except TypeError:
		ircrypt_error('Error in IRCrypt key exchange', weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# Decrypt
        (ret, out, err) = ircrypt_gnupg(message, '--homedir',
                ircrypt_gpg_homedir, '-d')

	# Print error and quit key exchange if necessary
	if ret:
		ircrypt_error(err, weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-INTERNAL-ERROR' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# Remove old messages from memory
	try:
		del ircrypt_sym_key_memory[catchword]
	except KeyError:
		pass

	target = '%s/%s' % (server, info['nick'])

	# Update symmetric key
	ircrypt_key_ex_memory[target].update(out)

	# If symmetric key is complete, send status back
	if ircrypt_key_ex_memory[target].parts == 2:
		weechat.command('','/mute -all notice -server %s %s '
				'>KEY-EX-SYM-RECEIVED' % (server, info['nick']))

		# If the symmetric key is also complete by the counterpart set symmetric
		# key
		if ircrypt_key_ex_memory[target].sym_received:
			weechat.command('','/ircrypt set-key -server %s %s %s' \
					% (server, info['nick'],
						base64.b64encode(ircrypt_key_ex_memory[target].sym_key)))

	return ''


def ircrypt_receive_key_ex_sym_received(server, args, info):
	'''This functions handles incomming >KEY-EX-SYM-RECEIVED notices'''
	global ircrypt_gpg_id, ircrypt_key_ex_memory

	target = '%s/%s' % (server, info['nick'])

	# No instance of KeyExchange: Error
	if not ircrypt_key_ex_memory.get(target):
		weechat.command('','/mute -all notice -server %s %s '
				'>UCRY-NO-KEY-EXCHANGE' % (server, info['nick']))
		return ''

	# No request for symmetric key exchange: Error and try to delete instance
	if (ircrypt_key_ex_memory[target].pub_key_send or
			ircrypt_key_ex_memory[target].pub_key_receive):
		ircrypt_error('Error in IRCrypt key exchange', weechat.current_buffer())
		weechat.command('','/mute -all notice -server %s %s'
				'>UCRY-NO-REQUEST-FOR-SYMMETRIC-KEY' % (server, info['nick']))
		try:
			del ircrypt_key_ex_memory[target]
		except KeyError:
			pass
		return ''

	# Remember that the counterpart has received the symmetric key
	ircrypt_key_ex_memory[target].sym_received = True

	# If the symmetric key is also complete by the counterpart set symmetric
	# key
	if ircrypt_key_ex_memory[target].parts == 2:
			weechat.command('','/ircrypt set-key -server %s %s %s' \
					% (server, info['nick'],
						base64.b64encode(ircrypt_key_ex_memory[target].sym_key)))

	return ''


def ircrypt_config_init():
	''' This method initializes the configuration file. It creates sections and
	options in memory and prepares the handling of key sections.
	'''
	global ircrypt_config_file, ircrypt_config_section, ircrypt_config_option
	ircrypt_config_file = weechat.config_new('ircrypt-keyex', 'ircrypt_config_reload_cb', '')
	if not ircrypt_config_file:
		return

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

	# public key identifier
	ircrypt_config_section['asym_id'] = weechat.config_new_section(
			ircrypt_config_file, 'asym_id', 0, 0,
			'ircrypt_config_asym_id_read_cb', '',
			'ircrypt_config_asym_id_write_cb', '', '', '', '', '', '', '')
	if not ircrypt_config_section['asym_id']:
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


def ircrypt_config_asym_id_read_cb(data, config_file, section_name, option_name,
		value):
	'''Read elements of the key section from the configuration file.
	'''
	global ircrypt_asym_id

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


def ircrypt_command_list():
	'''ircrypt command to list fingerprints'''
	global ircrypt_asym_id

	# Collect fingerprints
	out = ''
	for servchan,ids in ircrypt_asym_id.iteritems():
		out = out + '%s : %s\n' % (servchan.lower(), ids)

	# Print output
	if out: out = 'Fingerprint:\n' + out
	else: out = 'No known Fingerprints'
	ircrypt_info(out)

	return weechat.WEECHAT_RC_OK


def ircrypt_command_start(server, nick):
	'''This function is called when the user starts a key exchange'''
	global ircrypt_asym_id, ircrypt_key_ex_memory, ircrypt_gpg_id

	# Check for ircrypt plugin
	if not ircrypt_check_ircrypt:
		return weechat.WEECHAT_RC_OK

	# Check if own gpg key exists
	if not ircrypt_gpg_id:
		ircrypt_error('No GPG key generated')
		return weechat.WEECHAT_RC_ERROR

	# Send >KEY-EX-PING with optional gpg fingerprint and create instance of
	# KeyExchange
	target = '%s/%s' % (server, nick)
	gpg_id = ircrypt_asym_id.get(target.lower())
	text = '(This is a message to start a key exchange via the IRCrypt addon' \
			'IRCrypt-KeyEx. To do so you have to install IRCrypt-KeyEx)'
	if gpg_id:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PING %s %s' \
				% (server, nick, gpg_id, text))
		ircrypt_key_ex_memory[target] = KeyExchange(False, True)
	else:
		weechat.command('','/mute -all notice -server %s %s >KEY-EX-PING %s' \
				% (server, nick, text))
		ircrypt_key_ex_memory[target] = KeyExchange(True, True)

	# print information
	ircrypt_info('Start key exchange with %s on server %s. This may take some '
			'time, because there are many messages to exchange. You will also not '
			'get a feedback if %s did not install the addon IRCrypt-KeyEx.' \
			% (nick,	server, nick))

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
	'''Hook to handle the /ircrypt-keyex weechat command.'''
	global ircrypt_asym_id

	argv = [a for a in args.split(' ') if a]

	if argv and not argv[0] in ['list', 'remove-public-key', 'start']:
		ircrypt_error('%sUnknown command. Try  /help ircrypt-keyex', buffer)
		return weechat.WEECHAT_RC_ERROR

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
		ircrypt_error('Unknown Server. Please use -server to specify server', buffer)
		return weechat.WEECHAT_RC_ERROR

	# For the remaining commands we need at least one additional argument
	if len(argv) < 2:
		return weechat.WEECHAT_RC_ERROR

	target = '%s/%s' % (server, argv[1])

	if argv[0] == 'start':
		if len(argv) == 2:
			return ircrypt_command_start(server, argv[1])
		return weechat.WEECHAT_RC_ERROR

	# Remove public key from another user
	if argv[0] == 'remove-public-key':
		if len(argv) != 2:
			return weechat.WEECHAT_RC_ERROR
		return ircrypt_command_remove_public_key(target)

	# Error if command was unknown
	return weechat.WEECHAT_RC_ERROR


def ircrypt_notice_hook(data, msgtype, server, args):

	info = weechat.info_get_hashtable('irc_message_parse', { 'message': args })

	if '>UCRY-INTERNAL-ERROR' in args:
		ircrypt_error('%s on server %s reported an error during the key exchange' \
				% (info['nick'], server), weechat.current_buffer())
		return ''
	elif '>UCRY-NO-KEY-EXCHANGE' in args:
		ircrypt_error('%s on server %s reported an error during the key exchange' \
				% (info['nick'], server), weechat.current_buffer())
		return ''
	elif '>UCRY-PING-WITH-INVALID-FINGERPRINT' in args:
		ircrypt_error('%s on server %s reported that your fingerprint known does'
				'not match his own fingerprint' % (info['nick'], server),
				weechat.current_buffer())
		return ''
	elif '>UCRY-NO-REQUEST-FOR-PUBLIC-KEY' in args:
		ircrypt_error('%s on server %s reported an error during the key exchange' \
				% (info['nick'], server), weechat.current_buffer())
		return ''
	elif '>UCRY-NO-REQUEST-FOR-SYMMETRIC-KEY' in args:
		ircrypt_error('%s on server %s reported an error during the key exchange' \
				% (info['nick'], server), weechat.current_buffer())
		return ''
	# Different hooks
	elif '>KEY-EX-PING' in args:
		return ircrypt_receive_key_ex_ping(server, args, info)
	elif '>KEY-EX-PONG' in args:
		return ircrypt_receive_key_ex_pong(server, args, info)
	elif '>KEY-EX-NEXT-PHASE' in args:
		return ircrypt_receive_next_phase(server, args, info)
	elif '>KEY-EX-PUB-RECEIVED' in args:
		return ircrypt_receive_key_ex_pub_received(server, args, info)
	elif '>SYM-EX-' in args:
		return ircrypt_sym_key_get(server, args, info)
	elif '>KEY-EX-SYM-RECEIVED' in args:
		return  ircrypt_receive_key_ex_sym_received(server, args, info)
	elif '>PUB-EX-' in args:
		return ircrypt_public_key_get(server, args, info)

	return args


def ircrypt_load(data, signal, ircrypt_path):
	global ircrypt
	if ircrypt_path.endswith('ircrypt.py'):
		ircrypt = imp.load_source('ircrypt', ircrypt_path)
		ircrypt_init()
	return weechat.WEECHAT_RC_OK


def ircrypt_check_ircrypt():
	infolist = weechat.infolist_get('python_script', '', 'ircrypt')
	weechat.infolist_next(infolist)
	ircrypt_path = weechat.infolist_string(infolist, 'filename')
	weechat.infolist_free(infolist)
	return ircrypt_path


def ircrypt_init():
	# Initialize configuration
	ircrypt_config_init()
	ircrypt_config_read()
	# Look for GnuPG binary
	ircrypt_check_binary()
	if ircrypt_gpg_binary:
		# Initialize public key authentification
		ircrypt_gnupg_init()
		# Register Hooks
		weechat.hook_modifier('irc_in_notice',   'ircrypt_notice_hook', '')
		weechat.hook_command('ircrypt-keyex', 'Commands of the Addon IRCrypt-keyex',
				'[list] | remove-public-key [-server <server>] <nick> ',
				SCRIPT_HELP_TEXT,
				'list || remove-public-key %(nicks)|-server %(irc_servers) %- ',
				'ircrypt_command', '')
	else:
		ircrypt_error('GnuPG not found', weechat.current_buffer())


# register plugin
if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
		SCRIPT_DESC, 'ircrypt_unload_script', 'UTF-8'):

	ircrypt_path = ircrypt_check_ircrypt()
	if ircrypt_path:
		ircrypt = imp.load_source('ircrypt', ircrypt_path)
		ircrypt_init()
	else:
		weechat.hook_signal('python_script_loaded', 'ircrypt_load', '')


def ircrypt_unload_script():
	'''Hook to ensure the configuration is properly written to disk when the
	script is unloaded.
	'''
	ircrypt_config_write()
	return weechat.WEECHAT_RC_OK
