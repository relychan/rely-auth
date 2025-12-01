# RelyAuth

RelyAuth is the universal authenticator service for verifying request credentials that's inspired by [Hasura GraphQL Engine's Authentication](https://hasura.io/docs/3.0/auth/overview/).

## Features

- `Multi-platform support`: Works with Hasura GraphQL Engine and DDN via webhook mode.
- `Multiple auth modes`: API Key, JWT, Webhook, and more.
- `Fallback strategies`: Provides authentication redundancy.
- `Flexible data transformation`: Uses [JMESPath](https://jmespath.org/) and Go template for data manipulation.
