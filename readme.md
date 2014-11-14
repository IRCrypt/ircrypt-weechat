weechat-ircrypt
===============

This is the reference implementation of the [IRCrypt
protocol](https://github.com/IRCrypt/documentation). It provides an encryption
layer for IRC using standardized and well proven techniques for encryption.

This plug-in can be used for *Weechat*. It is still work-in-progress, but can
already be used to send and receive messages encrypted with cryptographically
strong symmetric ciphers.

IRCrypt supports symmetric encryption with all ciphers supported by
GnuPG and key exchange with public key authentication. For this IRCrypt creates
an own GnuPG homefolder and generates a key only used in IRCrypt. Other public
keys related to IRCrypt are also stored in that folder and do not inflict with
other GnuPG folder.

Requirements
------------

 - Weechat with support for Python extensions
 - GnuPG v1 or v2
