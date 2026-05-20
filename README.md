# toyaes
[![CodeQL](https://github.com/blck-snwmn/toyaes/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/blck-snwmn/toyaes/actions/workflows/github-code-scanning/codeql)
[![Go test&lint](https://github.com/blck-snwmn/toyaes/actions/workflows/test.yaml/badge.svg)](https://github.com/blck-snwmn/toyaes/actions/workflows/test.yaml)


Toy implementation of AES and GCM written in Go.

See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

## Development

CLI tools (`golangci-lint`, `lefthook`) are managed by [aqua](https://aquaproj.github.io/) with versions pinned in [aqua.yaml](aqua.yaml).

### Install tools

Install aqua itself first (see the [aqua installation guide](https://aquaproj.github.io/docs/install)), then install the pinned tools:

```
aqua install
```

### Set up git hooks

[lefthook](lefthook.yml) runs `golangci-lint` on staged `*.go` files before each commit. Register the hooks once after cloning:

```
lefthook install
```

### Lint

```
golangci-lint run --enable=gosec
```

## Test

```
go test
```
