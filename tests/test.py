import sys, os
sys.path.append((os.path.dirname(__file__) or '.') + '/..')
import ircrypt
import unittest


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
		encmsg = b'jA0EAwMCDvsNfqg4RyZgyRqTSfC2WSDIQm4GtvrW4WSq2l7gxGkQ9qIYiA=='
		encmsg = base64.b64decode(encmsg)
		(ret, out, err) = ircrypt.ircrypt_gnupg(b'test\n' + encmsg,
				'--passphrase-fd', '-', '-d')
		self.assertFalse(ret)
		self.assertEqual(out, b'test')


	def test_split_message(self):
		cmd = 'PRIVMSG #test '
		pre = 'CRY'
		msg = 'Loremipsumdolorsitametconsecteturadipiscing'
		result = 'PRIVMSG #test :>CRY-1 secteturadipiscing\n' \
				'PRIVMSG #test :>CRY-0 Loremipsumdolorsitametcon'
		ircrypt.MAX_PART_LEN = 25
		self.assertEqual(ircrypt.ircrypt_split_msg(cmd, pre, msg), result)
		ircrypt.MAX_PART_LEN = 300


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


	def test_ircrypt_info(self):
		ircrypt.ircrypt_info('test')
		ircrypt.ircrypt_info('test', 'buffer')


	def test_ircrypt_warn(self):
		ircrypt.ircrypt_warn('test')
		ircrypt.ircrypt_warn('test', 'buffer')


	def test_ircrypt_error(self):
		ircrypt.ircrypt_error('test', 'buffer')


	def test_command_set_keys(self):
		try:
			del ircrypt.ircrypt_keys['testserver/#test']
		except:
			pass
		ret = ircrypt.ircrypt_command_set_keys('testserver/#test', 'testkey')
		self.assertEqual(ircrypt.ircrypt_keys.get('testserver/#test'), 'testkey')
		self.assertEqual(ret,'OK')


	def test_command_remove_keys(self):
		ircrypt.ircrypt_keys['testserver/#test'] = 'testkey'
		ret = ircrypt.ircrypt_command_remove_keys('testserver/#test')
		self.assertEqual(ircrypt.ircrypt_keys.get('testserver/#test'), None)
		self.assertEqual(ret, 'OK')
		ret = ircrypt.ircrypt_command_remove_keys('testserver/#test')
		self.assertEqual(ret, 'OK')


	def test_command_set_cip(self):
		try:
			del ircrypt.ircrypt_cipher['testserver/#test']
		except:
			pass
		ret = ircrypt.ircrypt_command_set_cip('testserver/#test', 'TWOFISH')
		self.assertEqual(ircrypt.ircrypt_cipher.get('testserver/#test'), 'TWOFISH')
		self.assertEqual(ret,'OK')


	def test_command_remove_cip(self):
		ircrypt.ircrypt_cipher['testserver/#test'] = 'TWOFISH'
		ret = ircrypt.ircrypt_command_remove_cip('testserver/#test')
		self.assertEqual(ircrypt.ircrypt_cipher.get('testserver/#test'), None)
		self.assertEqual(ret, 'OK')
		ret = ircrypt.ircrypt_command_remove_cip('testserver/#test')
		self.assertEqual(ret, 'OK')


	def test_command_list(self):
		cip = {'testserver/#test1' : 'TWOFISH', 'testserver/#test2' : 'AES'}
		keys = {'testserver/#test1' : 'testkey', 'testserver/#test2' : 'testkey'}
		ircrypt.ircrypt_cipher = {}
		ircrypt.ircrypt_keys = {}
		ret = ircrypt.ircrypt_command_list()
		self.assertEqual(ret, 'OK')
		ircrypt.ircrypt_cipher = {'testserver/#test' : 'TWOFISH'}
		ircrypt.ircrypt_keys = {'testserver/#test' : 'testkey'}
		ret = ircrypt.ircrypt_command_list()
		self.assertEqual(ret, 'OK')


if __name__ == '__main__':
	unittest.main()
