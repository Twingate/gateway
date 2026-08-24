# Twingate Gateway

[![CI](https://github.com/Twingate/gateway/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/Twingate/gateway/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/Twingate/gateway/branch/master/graph/badge.svg)](https://codecov.io/gh/Twingate/gateway)
[![Dockerhub](https://img.shields.io/badge/dockerhub-images-info.svg?logo=Docker)](https://hub.docker.com/r/twingate/gateway)

> [!IMPORTANT]
> **Available Now.** Twingate Identity Firewall is currently available and free for up to five Kubernetes, SSH or Web App resources. For additional pricing information, please contact Twingate.

The Gateway is part of [Twingate Identity Firewall](https://www.twingate.com/docs/identity-firewall). It is a Layer 7 reverse proxy deployed within your environment that enables identity propagation and comprehensive auditing for upstream services such as Kubernetes API servers, SSH servers and web applications.

[Demo](https://youtu.be/kLE9txLo8Kg?si=iUrjzFuILMwnWCVI&t=1038) | [Wiki](https://github.com/Twingate/gateway/wiki) | [How It Works](https://github.com/Twingate/gateway/wiki/How-It-Works)

## Key Benefits

- **Seamless Identity Propagation:** Passes user identity through to upstream services, eliminating double authentication and removing the need for plaintext credentials on end-user machines.
- **Compliance-Ready Auditing:** All user activity is logged and attributed to specific identities, with session recording and replay for forensic review and compliance requirements.
- **Simplified Policy Management:** A unified policy engine governs both network and application access, reducing management overhead and eliminating credential sprawl.

## Supported Protocols

### Kubernetes

Secure access to private Kubernetes clusters with identity propagation, RBAC integration, and session recording for `kubectl` commands.

- [Overview](https://github.com/Twingate/gateway/wiki/Kubernetes-Overview)
- [Quick Start Guide](https://github.com/Twingate/gateway/wiki/Kubernetes-Quick-Start-Guide)

### SSH

Secure access to SSH servers with certificate-based authentication, CA management, and full channel support (shell, exec, SFTP, port forwarding).

- [Overview](https://github.com/Twingate/gateway/wiki/SSH-Overview)
- [Quick Start Guide](https://github.com/Twingate/gateway/wiki/SSH-Quick-Start-Guide)

### Web App *(Coming Soon)*

## Support

- For general issues using this gateway please open a GitHub issue.
- For account specific issues, please visit the [Twingate forum](https://forum.twingate.com/)
  or open a [support ticket](https://help.twingate.com/)

## Developers

- See [Developer Guide](https://github.com/Twingate/gateway/wiki/Developers) for how to set up a development environment and release process.
