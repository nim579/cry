#!/usr/bin/env coffee

pkg    = require './package.json'
crypto = require 'crypto'
fs     = require 'fs'
path   = require 'path'
os     = require 'os'
CN     = require 'constants'
pr     = require 'commander'
rl     = require 'readline'


SSH_PATH    = path.resolve os.homedir(), '.ssh'
PRI_PATH    = path.resolve SSH_PATH, 'rsa.pem'
PUB_PATH    = path.resolve SSH_PATH, 'rsa_pub.pem'
PASS_PATH   = path.resolve SSH_PATH, 'passkey'

replaceHome = (path)-> return path.replace /^\~/, os.homedir()


pr.command 'encpriv <text>'
 .description 'Encrypt with private key'
 .option '-e, --encoding [name]', 'Set encoding for exiting cipher', 'hex'
 .option '-R, --private [path]', 'Set path to public key', PRI_PATH
 .action (text, options)->
    key = fs.readFileSync replaceHome(options.private), 'utf8'
    buf = new Buffer(text, 'utf8')

    enc = crypto.privateEncrypt key, buf

    console.log '\nYour cipher:'
    console.log enc.toString options.encoding


pr.command 'encpub <text>'
 .description 'Encrypt with public key'
 .option '-e, --encoding [name]', 'Set encoding for exiting cipher', 'hex'
 .option '-P, --public [path]', 'Set path to public key', PUB_PATH
 .action (text, options)->
    key = fs.readFileSync replaceHome(options.public), 'utf8'
    buf = new Buffer(text, 'utf8')

    enc = crypto.publicEncrypt key, buf

    console.log '\nYour cipher:'
    console.log enc.toString options.encoding


pr.command 'decpriv <encrypted>'
 .description 'Decrypt with private key'
 .option '-e, --encoding [name]', 'Set encoding for encrypted string', 'hex'
 .option '-R, --private [path]', 'Set path to public key', PRI_PATH
 .action (encrypted, options)->
    key = fs.readFileSync replaceHome(options.private), 'utf8'

    buf = new Buffer(encrypted, options.encoding)

    dec = crypto.privateDecrypt key, buf

    console.log '\nDecrypted:'
    console.log dec.toString 'utf8'


pr.command 'decpub <encrypted>'
 .description 'Decrypt with public key'
 .option '-e, --encoding [name]', 'Set encoding for encrypted string', 'hex'
 .option '-P, --public [path]', 'Set path to public key', PUB_PATH
 .action (encrypted, options)->
    key = fs.readFileSync replaceHome(options.public), 'utf8'

    buf = new Buffer(encrypted, options.encoding)

    dec = crypto.publicDecrypt key, buf

    console.log '\nDecrypted:'
    console.log dec.toString 'utf8'


pr.command 'enc'
 .description 'Encrypt with cipher'
 .option '-f, --file [path]', 'Send file for encryption'
 .option '-t, --text [text]', 'Set text for encryption'
 .option '-e, --encoding [name]', 'Set encoding for returning cipher', 'hex'
 .option '-K, --passkey [path]', 'Set path to passkey', PASS_PATH
 .action (options)->
    return console.error 'No text or file' if not options.text and not options.file

    passkey = fs.readFileSync replaceHome options.passkey
    cipher = crypto.createCipher 'aes256', passkey

    if options.text
        enc = cipher.update options.text, 'utf8', options.encoding
        enc += cipher.final options.encoding

        console.log '\nYour cipher:'
        console.log enc

    else
        enc = ''
        stream = fs.createReadStream replaceHome options.file

        cipher.on 'readable', ->
            data = cipher.read()
            enc += data.toString options.encoding if data

        cipher.on 'end', ->
            console.log '\nYour cipher:'
            console.log enc

        stream.pipe(cipher)


pr.command 'dec <encrypted>'
 .description 'Decrypt with cipher'
 .option '-e, --encoding [name]', 'Set encoding for encrypted string', 'hex'
 .option '-K, --passkey [path]', 'Set path to passkey', PASS_PATH
 .action (encrypted, options)->
    passkey = fs.readFileSync replaceHome options.passkey
    cipher = crypto.createDecipher 'aes256', passkey

    dec = cipher.update encrypted, options.encoding, 'utf8'
    dec += cipher.final 'utf8'

    console.log '\nDecrypted:'
    console.log dec


pr.command 'sign <file_path>'
 .description 'Create sign for file'
 .option '-S, --save [path]', 'Save signature'
 .option '-e, --encoding [name]', 'Set encoding for returning passkey (if no save flag)', 'hex'
 .option '-R, --private [path]', 'Set path to public key', PRI_PATH
 .action (file, options)->
    key = fs.readFileSync replaceHome options.private

    sign = crypto.createSign 'RSA-SHA256'
    file = fs.readFileSync replaceHome file

    sign.update file
    signature = sign.sign key

    if options.save
        fs.writeFileSync replaceHome(options.save), signature
        console.log "Saved on", replaceHome(options.save)

    else
        console.log "Your signature:\n"
        console.log signature.toString options.encoding


pr.command 'verify <file_path>'
 .description 'Verify signed file'
 .option '-f, --file [path]', 'Set path to public key'
 .option '-t, --text [text]', 'Set path to public key'
 .option '-e, --encoding [name]', 'Set encoding signature text', 'hex'
 .option '-P, --public [path]', 'Set path to public key', PUB_PATH
 .action (file, options)->
    key = fs.readFileSync replaceHome options.public

    verify = crypto.createVerify 'RSA-SHA256'
    file = fs.readFileSync replaceHome file

    if options.text
        signature = new Buffer(options.text, options.encoding)

    else if options.file
        signature = fs.readFileSync replaceHome options.file

    verify.update file
    verified = verify.verify key, signature

    if verified
        console.log 'Verified'

    else
        console.log 'Unverified'


pr.command 'dhmake'
 .option '-s, --slave', false
 .option '-S, --save [path]', 'Save passkey'
 .option '-e, --encoding [name]', 'Set encoding for returning passkey (if no save flag)', 'hex'
 .description 'Make DH passkey'
 .action (options)->
    ask = rl.createInterface
          input:  process.stdin
          output: process.stdout

    unless options.slave
        ask.question 'Enter prime length: ', (length)->
            dh = crypto.createDiffieHellman Number length
            dh.generateKeys()

            console.log "Your master prime:", dh.getPrime('hex')
            console.log "Your master generator:", dh.getGenerator('hex')
            console.log "Your master public key:", dh.getPublicKey('hex')

            ask.question 'Enter slave public key: ', (key)->
                ask.close()
                passkey = dh.computeSecret key, 'hex'

                if options.save
                    fs.writeFileSync replaceHome(options.save), passkey
                    console.log "Saved on", replaceHome(options.save)

                else
                    console.log "\nYour passkey in (#{options.encoding}):"
                    console.log passkey.toString options.encoding

    else
        ask.question 'Enter master prime (in hex): ', (prime)->
            ask.question 'Enter master generator (in hex): ', (generator)->
                dh = crypto.createDiffieHellman prime, 'hex', generator, 'hex'
                dh.generateKeys()

                console.log "Your slave public key", dh.getPublicKey('hex')

                ask.question 'Enter master public key: ', (key)->
                    ask.close()

                    passkey = dh.computeSecret key, 'hex'

                    if options.save
                        fs.writeFileSync replaceHome(options.save), passkey
                        console.log "Saved on", replaceHome(options.save)

                    else
                        console.log "\nYour passkey in (#{options.encoding}):"
                        console.log passkey.toString options.encoding


pr.command 'ecdhmake'
 .option '-c, --curve [curve]', 'Set Elliptic Curve name', 'secp521r1'
 .option '-S, --save [path]', 'Save passkey'
 .option '-e, --encoding [name]', 'Set encoding for returning passkey', 'hex'
 .description 'Make ECDH passkey'
 .action (options)->
    ask = rl.createInterface
          input:  process.stdin
          output: process.stdout

    dh = crypto.createECDH options.curve
    dh.generateKeys()

    console.log "Your public key:", dh.getPublicKey('hex')

    ask.question 'Enter other public key: ', (key)->
        ask.close()

        passkey = dh.computeSecret key, 'hex'

        if options.save
            fs.writeFileSync replaceHome(options.save), passkey
            console.log "Saved on", replaceHome(options.save)

        else
            console.log "\nYour passkey in (#{options.encoding}):"
            console.log passkey.toString options.encoding


pr
.version pkg.version
.parse process.argv
