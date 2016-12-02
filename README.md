# cry tool

## Install

```
npm install -g cry-cli
```

## Useage

```
cry enc -t "Test text"
```

### Commands

* **encpriv** `<text>` — Encrypt with private key
* **encpub** `<text>` — Encrypt with public key
* **decpriv** `<encrypted>` — Decrypt with private key
* **decpub** `<encrypted>` — Decrypt with public key
* **enc** `[options]` — Encrypt with cipher
* **dec** `[options]` — Decrypt with cipher
* **sign** `<file_path>` — Create sign for file
* **verify** `<file_path>` — Verify signed file
* **dhmake** `[options]` — Make DH passkey
* **ecdhmake** `[options]` — Make ECDH passkey

More information about commands:
```
cry --help
```

More information about some command:
```
cry <command> --help
```
