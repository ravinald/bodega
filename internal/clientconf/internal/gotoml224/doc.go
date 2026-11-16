// Package toml is the decoder of github.com/pelletier/go-toml/v2 at tag
// v2.2.4, the version containerd v2.2.0 parses hosts.toml with, copied
// unchanged apart from its import paths, without the encoder, and with the
// two type-mismatch messages in unmarshaler.go passed through a constant
// "%s" format so go vet accepts them. The module
// graph resolves go-toml to a later release whose grammar accepts TOML 1.1
// syntax this one rejects, and a hosts.toml containerd rejects is one it
// discards. Only the hosts.toml reader in clientconf imports this copy; do
// not update it past the go-toml release the pinned containerd uses.
package toml
