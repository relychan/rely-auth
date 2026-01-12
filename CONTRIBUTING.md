# Contributing

## Guideline

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code:

- Follows the guidelines in [CLAUDE.md](./CLAUDE.md).
- Includes appropriate tests.
- Passes all existing tests.
- Is properly formatted (`make lint-fix`).

## Development

### Prerequisites

- Go 1.25.5 or later.
- Basic understanding of authentication concepts.

### Building from Source

```bash
git clone https://github.com/relychan/rely-auth.git
cd rely-auth
go build ./...
```

### Running Tests

```bash
# Run all tests
make test
```

### Code Quality

This project follows idiomatic Go practices. See [CLAUDE.md](./CLAUDE.md) for detailed development guidelines.

```bash
# Format code
make format

# Run linter
make lint-fix
```
