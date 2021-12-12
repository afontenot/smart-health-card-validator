# smart-health-card-validator
a pretty solid proof of concept decoder and validator for SMART health cards

Wrote this on a weekend afternoon for fun. Probably some outstanding bugs.

This is a very small decoder / validator library for the SMART health record
cards used by many states and health institutions. Most of the heavy lifting
is done by [jwcrypto](https://github.com/latchset/jwcrypto/).

It supports:

1. Automatically downloading a list of trusted certificate issuers, from a
source like the
[VCI Directory](https://github.com/the-commons-project/vci-directory/blob/main/vci-issuers.json).
Certificates can also be cached to avoid constantly redownloading them.

2. Decoding all the information contained in a SMART QR code string
(e.g. shc:/XXXXXXX), and proving that it was signed by the issuer that
it says it was signed by. It is also possible to detect whether the issuer
is trusted or not.

It does not support scanning a QR code. Use a tool like
[Zbar](http://zbar.sourceforge.net/) if you are trying to build a scanner
around this library.

Usage is pretty self explanatory (and there's an example in the file), but
additional documentation would be useful and is planned.
