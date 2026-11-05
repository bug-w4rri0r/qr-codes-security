Trust store of the reader: put only Root CA **public** keys (`*_pub.pem`) here.
App keys do not belong here; App keys are trusted only through a certificate signed by a Root.
Files other than `*.pem` are ignored by `qr-read.py`.
