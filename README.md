# Sec Tools

This is a collection of tools/functions that will be useful later on in a development process as one begins to connect microervices together and enters the phase of the project where security concerns must be brought front and center.

## cifunc.sh

Cifunc was a quick script to generate a secure bootable usb drive that highlighted the need for me to finally make a security library that could generate secrets and such properly.

The generate_secret and create_secret functions are replaced by cryptkeeper.py

the rest of the script is fairly simple copy and extact work and can probably be moved into ansible roles.


## names.py

A very babbin script, right now only generates random UUID's but will be beefed up later with the elements necessary to generate proper randomized names and identity related data

## cryptkeeper.py

Encryption library that can create secrets and hashes using pbkdf2_sha256. More complete than the others, has the following functionality:

- Generate random secret/salt with length and symbol options
- hash a value with md5
- encode a value to base64
- decode a value from base64
- hash a value using pbkdf2_sha256
- pbkdf2_sha256 iterations, salt, and length are customizable
- compare hashed values against regenerated hash
- End-to-End demo function
- might show how a block chain works for an article later