# Host SSH key pair

Generated key pair using:

```bash
ssh-keygen -t ed25519 -C "host" -f host
```

Sign the host public key with the CA:

```bash
ssh-keygen -s ../ca/ca -I "host:127.0.0.1" -n "127.0.0.1" -h host.pub
```
