# RelyAuth

RelyAuth is a universal authentication service for verifying request credentials, inspired by [Hasura GraphQL Engine's Authentication](https://hasura.io/docs/3.0/auth/overview/).

## Features

- **Multi-platform support**: Works with Hasura GraphQL Engine and DDN via webhook mode.
- **Multiple auth modes**: API Key, JWT, Webhook, and more.
- **Fallback strategies**: Provides authentication redundancy with configurable fallback chains.
- **Flexible data transformation**: Uses [JMESPath](https://jmespath.org/) and Go templates for data manipulation.
- **IP allowlisting**: Support for IP-based access control with CIDR notation.
- **Header-based authentication**: Extract credentials from headers, query parameters, or cookies.
- **Pattern matching**: Regex-based pattern matching for flexible credential validation.

## Get Started

### With Hasura

You can use RelyAuth as a webhook auth service. Read the tutorial at [relychan.com/docs/auth/hasura](https://relychan.com/docs/auth/hasura).

## Documentation

Read the complete RelyAuth documentation at [relychan.com/docs/auth/](https://relychan.com/docs/auth/)

## AI Assistance Disclosure

This project has been developed with assistance from AI coding tools, including:

- Test case development.
- Documentation improvements.
- Code review and optimization suggestions.

All AI-generated code has been reviewed, tested, and validated by human developers to ensure quality, security, and correctness. The AI tools serve as development accelerators while maintaining human oversight and decision-making.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [Hasura GraphQL Engine's Authentication](https://hasura.io/docs/3.0/auth/overview/).
- Built with Go and leverages excellent open-source libraries.
- Community contributions and feedback.

## Support

- **Documentation**: [relychan.com/docs/auth/](https://relychan.com/docs/auth/)
- **Issues**: [GitHub Issues](https://github.com/relychan/rely-auth/issues)

---

**Note**: This is an authentication service. Always follow security best practices when deploying to production environments.
