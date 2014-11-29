'''
Some mock functions to use for testing weechat plug-ins
'''

config = {}

WEECHAT_RC_OK = 'OK'

def color(*args, **kwargs):
	return ''

def config_string(key):
	return config.get(key)


def prnt(_, arg):
	#print(arg)
	return

def config_option_set(key, val, _):
	config[key] = val

def info_get_hashtable(*args):
	return {'channel':'#test', 'nick':'testnick'}

def buffer_search(*args):
	return ''

def config_get(key):
	return key

def prefix(*args):
	return ''

def current_buffer():
	return ''
