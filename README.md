# opensource_taig
Lets create an open source version of the latest TaiG jailbreak.

## Status

Currently decompilation of the taig untether binary in progress.
Binary in question has the following properties:

* Filename: taig
* Size: 312672 bytes
* SHA1: 065783b31dd2016cc3d48e6b174fcc12e2dff337
* MD5: 38dd260a09690465adaf872268def218
* SHA256: df9c72d2f7be90847affdeec6e18483e985e093ead3264c962883d6ae103758b


taig binary contains a number of obfuscated strings:

* IOPMrootDomain
* IOHIDResource
* IOHIDLibUserClient
* IOHIDEventService
* IOUserClientClass
* ReportDescriptor
* ReportInterval

Components found in the untether so far:

* planetbeing's patchfinder - https://github.com/planetbeing/ios-jailbreak-patchfinder/blob/master/patchfinder.c
* libtar
* google-toolbox-for-mac - https://code.google.com/p/google-toolbox-for-mac/
