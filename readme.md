weechat-ircrypt
===============

This is the reference implementation of the [IRCrypt
protocol](https://github.com/IRCrypt/documentation). It provides an encryption
layer for IRC using standardized and well proven techniques for encryption.

This plug-in can be used for *Weechat*. It is still work-in-progress, but can
already be used to send and receive messages encrypted with cryptographically
strong symmetric ciphers.


Advanced vs Basic Version
-------------------------

The Basic version supports symmetric encryption with all ciphers supported by
GnuPG. The advanced version adds support for key exchange and communication
with asymmetric encryption (public key cryptography).

For most people, the basic version should work and do what they want and
expect. For use on a server it is even recommended to use the basic version as
the advanced version requires a graphical user interface (GPG Pinentry).

If you are running weechat locally, have a graphical window manager running and
want to have more features, you may want to try the advanced version. In any
case, the symmetrical message encryption of both versions will be compatible
with each other.


Requirements
------------

 - Weechat with support for Python extensions
 - GnuPG v1 or v2
 - Pinentry (for advanced version)
