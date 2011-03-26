S3G Toolkit
===========

These are simple command-line tools for manipulating the S3G format, used by
RepRap and MakerBot 3D printers via the ReplicatorG host software.


Building
--------

The Toolkit has no external dependencies and should build on any Unix-like
system (tested primarily on Mac OS X).  Just type:

    make


Using
-----

These tools work with the S3G format as sent on the wire.  If you've captured
an S3G command stream from a serial line, it will work without modification.

If you've saved an S3G file from ReplicatorG, it's in a slightly different
format.  You will need to use `s3g-reencap` to convert it before passing it to
other tools.  For example,

    cat myfile.s3g | s3g-reencap | s3g-send /dev/ttyUSB0
