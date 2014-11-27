import sys
sys.path.append('..')
import ircrypt
import unittest

ircrypt_config_option = {}
ircrypt_config_option['binary'] = ''

class TestSequenceFunctions(unittest.TestCase):

	def test_find_gpg(self):
		binary, version = ircrypt.ircrypt_find_gpg_binary(['python'])
		self.assertEqual(binary, 'python')


	def test_check_binary(self):
		ircrypt.ircrypt_check_binary()
		self.assertTrue(ircrypt.weechat.config.get('ircrypt.general.binary'))


	def test_gnupg(self):
		import base64
		# 'test' encrypted with password 'test'
		encmsg = 'jA0EAwMCDvsNfqg4RyZgyRqTSfC2WSDIQm4GtvrW4WSq2l7gxGkQ9qIYiA=='
		encmsg = base64.b64decode(encmsg)
		(ret, out, err) = ircrypt.ircrypt_gnupg('test\n' + encmsg,
				'--passphrase-fd', '-', '-d')
		self.assertFalse(ret)
		self.assertEqual(out, 'test')


	def test_plain(self):
		import time
		ircrypt.ircrypt_message_plain['testserver/#test'] = (time.time(), 'testmsg')
		ircrypt.ircrypt_config_option['unencrypted'] = 'ircrypt.marker.unencrypted'
		ircrypt.weechat.config['ircrypt.marker.unencrypted'] = '[P]'
		msg = ircrypt.ircrypt_encrypt_hook('', '', 'testserver', 'PRIVMSG #test :testmsg')
		self.assertEqual(msg, 'PRIVMSG #test :testmsg')


	def test_encryption(self):
		ircrypt.ircrypt_keys['testserver/#test'] = 'testkey'
		ircrypt.ircrypt_cipher['testserver/#test'] = 'TWOFISH'
		ircrypt.ircrypt_config_option['sym_cipher'] = None
		encmsg = ircrypt.ircrypt_encrypt_hook('', '', 'testserver', 'PRIVMSG #test :test')
		self.assertTrue(encmsg.startswith('PRIVMSG #test :>CRY-0 '))
		encmsg = ':testnick!~testuser@example.com ' + encmsg
		decmsg = ircrypt.ircrypt_decrypt_hook('', '', 'testserver', encmsg)
		self.assertEqual(decmsg, ':testnick!~testuser@example.com PRIVMSG #test :test')


if __name__ == '__main__':
	unittest.main()