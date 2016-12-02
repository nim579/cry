#!/usr/bin/env coffee

pkg    = require './package.json'
crypto = require 'crypto'
stream = require 'stream'
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
 .option '-e, --encoding <name>', 'Set encoding for exiting cipher', 'hex'
 .option '-R, --private <path>', 'Set path to private key', PRI_PATH
 .action (text, options)->
    key = fs.readFileSync replaceHome(options.private), 'utf8'
    buf = new Buffer(text, 'utf8')

    enc = crypto.privateEncrypt key, buf

    console.log enc.toString options.encoding


pr.command 'encpub <text>'
 .description 'Encrypt with public key'
 .option '-e, --encoding <name>', 'Set encoding for exiting cipher', 'hex'
 .option '-P, --public <path>', 'Set path to public key', PUB_PATH
 .action (text, options)->
    key = fs.readFileSync replaceHome(options.public), 'utf8'
    buf = new Buffer(text, 'utf8')

    enc = crypto.publicEncrypt key, buf

    console.log enc.toString options.encoding


pr.command 'decpriv <encrypted>'
 .description 'Decrypt with private key by encrypted string'
 .option '-e, --encoding <name>', 'Set encoding for encrypted string', 'hex'
 .option '-R, --private <path>', 'Set path to private key', PRI_PATH
 .action (encrypted, options)->
    key = fs.readFileSync replaceHome(options.private), 'utf8'

    buf = new Buffer(encrypted, options.encoding)

    dec = crypto.privateDecrypt key, buf

    console.log dec.toString 'utf8'


pr.command 'decpub <encrypted>'
 .description 'Decrypt with public key by encrypted string'
 .option '-e, --encoding <name>', 'Set encoding for encrypted string', 'hex'
 .option '-P, --public <path>', 'Set path to public key', PUB_PATH
 .action (encrypted, options)->
    key = fs.readFileSync replaceHome(options.public), 'utf8'

    buf = new Buffer(encrypted, options.encoding)

    dec = crypto.publicDecrypt key, buf

    console.log dec.toString 'utf8'


pr.command 'enc'
 .description 'Encrypt with cipher by text or file'
 .option '-f, --file <path>', 'Send file for encryption'
 .option '-t, --text <text>', 'Send text for encryption'
 .option '-S, --save <path>', 'Save signature to path'
 .option '-e, --encoding <name>', 'Set encoding for exiting cipher (for console output)', 'hex'
 .option '-K, --passkey <path>', 'Set path to passkey for encryption', PASS_PATH
 .action (options)->
    return console.error 'No text or file' if not options.text and not options.file

    passkey = fs.readFileSync replaceHome options.passkey
    cipher = crypto.createCipher 'aes256', passkey

    if options.save
        write = fs.createWriteStream replaceHome options.save
        cipher.on 'end', -> console.log "Saved on", replaceHome(options.save)

    else
        write = new stream.Writable()
        write._write = (chunk, encoding, callback)->
            process.stdout.write chunk.toString options.encoding
            callback()

    if options.text
        cipher.write options.text, 'utf8'
        cipher.end()
        cipher.pipe(write)

    else
        read = fs.createReadStream replaceHome options.file
        read.pipe(cipher).pipe(write)


pr.command 'dec'
 .description 'Decrypt with cipher by encrypted string'
 .option '-f, --file <path>', 'Send file for decryption'
 .option '-t, --text <text>', 'Send text for decryption'
 .option '-S, --save <path>', 'Save signature to path'
 .option '-e, --encoding <name>', 'Set encoding for encrypted string (for console input)', 'hex'
 .option '-K, --passkey <path>', 'Set path to passkey for decryption', PASS_PATH
 .action (options)->
    return console.error 'No text or file' if not options.text and not options.file

    passkey = fs.readFileSync replaceHome options.passkey
    cipher = crypto.createDecipher 'aes256', passkey

    if options.save
        write = fs.createWriteStream replaceHome options.save
        cipher.on 'end', -> console.log "Saved on", replaceHome(options.save)

    else
        write = new stream.Writable()
        write._write = (chunk, encoding, callback)->
            process.stdout.write chunk.toString('utf8')
            callback()

    if options.text
        cipher.write options.text, options.encoding
        cipher.end()
        cipher.pipe(write)

    else
        read = fs.createReadStream replaceHome options.file
        read.pipe(cipher).pipe(write)


pr.command 'sign <file_path>'
 .description 'Create sign for file'
 .option '-S, --save <path>', 'Save signature to path'
 .option '-e, --encoding <name>', 'Set encoding for returning passkey (if no save flag)', 'hex'
 .option '-P, --private <path>', 'Set path to public key', PRI_PATH
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
        console.log signature.toString options.encoding


pr.command 'verify <file_path>'
 .description 'Verify signed file'
 .option '-f, --file <path>', 'Send path to signature file'
 .option '-s, --sign <string>', 'Send text of signature'
 .option '-e, --encoding <name>', 'Set encoding signature text (if text sended', 'hex'
 .option '-P, --public <path>', 'Set path to public key', PUB_PATH
 .action (file, options)->
    return console.error 'No sign string or file' if not options.sign and not options.file

    key = fs.readFileSync replaceHome options.public

    verify = crypto.createVerify 'RSA-SHA256'
    file = fs.readFileSync replaceHome file

    if options.sign
        signature = new Buffer(options.sign, options.encoding)

    else
        signature = fs.readFileSync replaceHome options.file

    verify.update file
    verified = verify.verify key, signature

    if verified
        console.log 'Verified'

    else
        console.log 'Unverified'


pr.command 'dhmake'
 .description 'Make DH passkey'
 .option '-s, --slave', 'Command for second client', false
 .option '-S, --save [path]', "Save passkey path (save to '#{PASS_PATH}' if flag)"
 .option '-e, --encoding <name>', 'Set encoding for returning passkey (if no save flag)', 'hex'
 .action (options)->
    ask = rl.createInterface
          input:  process.stdin
          output: process.stdout

    unless options.slave
        ask.question 'Enter prime length: ', (length)->
            dh = crypto.createDiffieHellman Number length
            dh.generateKeys()

            console.log "\nYour master prime:", dh.getPrime('hex')
            console.log "\nYour master generator:", dh.getGenerator('hex')
            console.log "\nYour master public key:", dh.getPublicKey('hex')

            ask.question '\nEnter slave public key: ', (key)->
                ask.close()
                passkey = dh.computeSecret key, 'hex'

                if options.save
                    options.save = PASS_PATH if options.save is true
                    fs.writeFileSync replaceHome(options.save), passkey
                    console.log "Saved on '#{replaceHome(options.save)}'"

                else
                    console.log "\nYour passkey in (#{options.encoding}):"
                    console.log passkey.toString options.encoding

    else
        ask.question 'Enter master prime (in hex): ', (prime)->
            ask.question '\nEnter master generator (in hex): ', (generator)->
                dh = crypto.createDiffieHellman prime, 'hex', generator, 'hex'
                dh.generateKeys()

                console.log "\nYour slave public key:", dh.getPublicKey('hex')

                ask.question '\nEnter master public key: ', (key)->
                    ask.close()

                    passkey = dh.computeSecret key, 'hex'

                    if options.save
                        options.save = PASS_PATH if options.save is true
                        fs.writeFileSync replaceHome(options.save), passkey
                        console.log "Saved on '#{replaceHome(options.save)}'"

                    else
                        console.log "\nYour passkey in (#{options.encoding}):"
                        console.log passkey.toString options.encoding


pr.command 'ecdhmake'
 .option '-c, --curve <curve>', 'Set Elliptic Curve name', 'secp521r1'
 .option '-S, --save [path]', "Save passkey path (save to '#{PASS_PATH}' if flag)"
 .option '-e, --encoding <name>', 'Set encoding for returning passkey (if no save flag)', 'hex'
 .description 'Make ECDH passkey'
 .action (options)->
    ask = rl.createInterface
          input:  process.stdin
          output: process.stdout

    dh = crypto.createECDH options.curve
    dh.generateKeys()

    console.log "Your public key:", dh.getPublicKey('hex')

    ask.question '\nEnter other public key: ', (key)->
        ask.close()

        passkey = dh.computeSecret key, 'hex'

        if options.save
            options.save = PASS_PATH if options.save is true
            fs.writeFileSync replaceHome(options.save), passkey
            console.log "Saved on '#{replaceHome(options.save)}'"

        else
            console.log "\nYour passkey in (#{options.encoding}):"
            console.log passkey.toString options.encoding


pr
.version pkg.version
.parse process.argv
