---
description: "Instructions for writing Go code following idiomatic Go practices and community standards"
applyTo: "**/*.go,**/go.mod,**/go.sum"
---

# Go Development Instructions

Follow idiomatic Go practices and community standards when writing Go code. These instructions are based on [Effective Go](https://go.dev/doc/effective_go), [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments), and [Google's Go Style Guide](https://google.github.io/styleguide/go/).

## General Instructions

- Write simple, clear, and idiomatic Go code
- Favor clarity and simplicity over cleverness
- Follow the principle of least surprise
- Keep the happy path left-aligned (minimize indentation)
- Return early to reduce nesting
- Prefer early return over if-else chains; use `if condition { return }` pattern to avoid else blocks
- Make the zero value useful
- Write self-documenting code with clear, descriptive names
- Document exported types, functions, methods, and packages
- Use Go modules for dependency management
- Leverage the Go standard library instead of reinventing the wheel (e.g., use `strings.Builder` for string concatenation, `filepath.Join` for path construction)
- Prefer standard library solutions over custom implementations when functionality exists
- Write comments in English by default; translate only upon user request
- Avoid using emoji in code and comments

## Naming Conventions

### Packages

- Use lowercase, single-word package names
- Avoid underscores, hyphens, or mixedCaps
- Choose names that describe what the package provides, not what it contains
- Avoid generic names like `util`, `common`, or `base`
- Package names should be singular, not plural

#### Package Declaration Rules (CRITICAL):

- **NEVER duplicate `package` declarations** - each Go file must have exactly ONE `package` line
- When editing an existing `.go` file:
  - **PRESERVE** the existing `package` declaration - do not add another one
  - If you need to replace the entire file content, start with the existing package name
- When creating a new `.go` file:
  - **BEFORE writing any code**, check what package name other `.go` files in the same directory use
  - Use the SAME package name as existing files in that directory
  - If it's a new directory, use the directory name as the package name
  - Write **exactly one** `package <name>` line at the very top of the file
- When using file creation or replacement tools:
  - **ALWAYS verify** the target file doesn't already have a `package` declaration before adding one
  - If replacing file content, include only ONE `package` declaration in the new content
  - **NEVER** create files with multiple `package` lines or duplicate declarations
- **When writing tests**:
  - Test files use the same package name as the code they test (white-box testing)
  - For black-box testing, append `_test` to package name: `package authmode_test`
  - Most tests should be white-box unless specifically testing public API only
- **Common mistake to avoid**:
  - DO NOT copy package declarations from other files without checking the directory
  - DO NOT assume package name from import path - always verify existing files

### Variables and Functions

- Use mixedCaps or MixedCaps (camelCase) rather than underscores
- Keep names short but descriptive
- Use single-letter variables only for very short scopes (like loop indices)
- Exported names start with a capital letter
- Unexported names start with a lowercase letter
- Avoid stuttering (e.g., avoid `http.HTTPServer`, prefer `http.Server`)

### Interfaces

- Name interfaces with -er suffix when possible (e.g., `Reader`, `Writer`, `Formatter`)
- Single-method interfaces should be named after the method (e.g., `Read` → `Reader`)
- Keep interfaces small and focused

### Constants

- Use MixedCaps for exported constants
- Use mixedCaps for unexported constants
- Group related constants using `const` blocks
- Consider using typed constants for better type safety

## Code Style and Formatting

### Formatting

- Always use `gofmt` to format code
- Use `goimports` to manage imports automatically
- Keep line length reasonable (no hard limit, but consider readability)
- Add blank lines to separate logical groups of code

### Comments

- Strive for self-documenting code; prefer clear variable names, function names, and code structure over comments
- Write comments only when necessary to explain complex logic, business rules, or non-obvious behavior
- Write comments in complete sentences in English by default
- Translate comments to other languages only upon specific user request
- Start sentences with the name of the thing being described
- Package comments should start with "Package [name]"
- Use line comments (`//`) for most comments
- Use block comments (`/* */`) sparingly, mainly for package documentation
- Document why, not what, unless the what is complex
- Avoid emoji in comments and code

### Error Handling

- Check errors immediately after the function call
- Don't ignore errors using `_` unless you have a good reason (document why)
- Wrap errors with context using `fmt.Errorf` with `%w` verb
- Create custom error types when you need to check for specific errors
- Place error returns as the last return value
- Name error variables `err`
- Keep error messages lowercase and don't end with punctuation

### Error Testing

- Always test error cases, not just happy paths
- Use `assert.ErrorContains(t, err, "expected message")` to verify error messages
- Test that errors are properly wrapped with context using `%w`
- Verify that appropriate error types/sentinels are returned
- Test error propagation through call chains

## Architecture and Project Structure

### Package Organization

- Follow standard Go project layout conventions
- Keep `main` packages in `cmd/` directory
- Use `internal/` for packages that shouldn't be imported by external projects
- Group related functionality into packages
- Avoid circular dependencies

### Dependency Management

- Use Go modules (`go.mod` and `go.sum`)
- Keep dependencies minimal
- Regularly update dependencies for security patches
- Use `go mod tidy` to clean up unused dependencies
- Vendor dependencies only when necessary

## Type Safety and Language Features

### Type Definitions

- Define types to add meaning and type safety
- Use struct tags for JSON, XML, database mappings
- Prefer explicit type conversions
- Use type assertions carefully and check the second return value
- Prefer generics over unconstrained types; when an unconstrained type is truly needed, use the predeclared alias `any` instead of `interface{}` (Go 1.18+)

### Pointers vs Values

- **Method receivers**:
  - Use pointer receivers when the method modifies the receiver
  - Use pointer receivers for large structs (>64 bytes as a guideline)
  - Use value receivers for small structs and when immutability is desired
  - Be consistent within a type's method set - don't mix pointer and value receivers
  - Consider the zero value when choosing pointer vs value receivers

- **Function parameters**:
  - Use pointer parameters when you need to modify the argument or for large structs
  - Use value parameters for small structs and when you want to prevent modification

- **Configuration structs**:
  - Use pointers for optional configuration fields
  - Allows distinguishing between "not set" (nil) and "set to zero value"
  - Example: `AllowedIPs *RelyAuthIPAllowListConfig`

- **Return values**:
  - Return pointers for large structs or when nil has meaning
  - Return `(*Type, error)` when the type might not be created
  - Return `(Type, error)` for small structs or when zero value is valid

### Interfaces and Composition

- Accept interfaces, return concrete types
- Keep interfaces small (1-3 methods is ideal)
- Use embedding for composition
- Define interfaces close to where they're used, not where they're implemented
- Don't export interfaces unless necessary

## Concurrency

### Goroutines

- Be cautious about creating goroutines in libraries; prefer letting the caller control concurrency
- If you must create goroutines in libraries, provide clear documentation and cleanup mechanisms
- Always know how a goroutine will exit
- Use `sync.WaitGroup` or channels to wait for goroutines
- Avoid goroutine leaks by ensuring cleanup

### Channels

- Use channels to communicate between goroutines
- Don't communicate by sharing memory; share memory by communicating
- Close channels from the sender side, not the receiver
- Use buffered channels when you know the capacity
- Use `select` for non-blocking operations

### Synchronization

- Use `sync.Mutex` for protecting shared state
- Keep critical sections small
- Use `sync.RWMutex` when you have many readers
- Choose between channels and mutexes based on the use case: use channels for communication, mutexes for protecting state
- Use `sync.Once` for one-time initialization
- WaitGroup usage by Go version:
  - If `go >= 1.25` in `go.mod`, use the new `WaitGroup.Go` method ([documentation](https://pkg.go.dev/sync#WaitGroup)):
    ```go
    var wg sync.WaitGroup
    wg.Go(task1)
    wg.Go(task2)
    wg.Wait()
    ```
  - If `go < 1.25`, use the classic `Add`/`Done` pattern

## Error Handling Patterns

### Creating Errors

- Use `errors.New` for simple static errors
- Use `fmt.Errorf` for dynamic errors
- Create custom error types for domain-specific errors
- Export error variables for sentinel errors
- Use `errors.Is` and `errors.As` for error checking

### Error Propagation

- Add context when propagating errors up the stack
- Don't log and return errors (choose one)
- Handle errors at the appropriate level
- Consider using structured errors for better debugging

## API Design

### HTTP Handlers

- Use `http.HandlerFunc` for simple handlers
- Implement `http.Handler` for handlers that need state
- Use middleware for cross-cutting concerns
- Set appropriate status codes and headers
- Handle errors gracefully and return appropriate error responses
- Router usage by Go version:
  - If `go >= 1.22`, prefer the enhanced `net/http` `ServeMux` with pattern-based routing and method matching
  - If `go < 1.22`, use the classic `ServeMux` and handle methods/paths manually (or use a third-party router when justified)

### JSON APIs

- Use struct tags to control JSON marshaling
- Validate input data
- Use pointers for optional fields
- Consider using `json.RawMessage` for delayed parsing
- Handle JSON errors appropriately

### HTTP Clients

- Keep the client struct focused on configuration and dependencies only (e.g., base URL, `*http.Client`, auth, default headers). It must not store per-request state
- Do not store or cache `*http.Request` inside the client struct, and do not persist request-specific state across calls; instead, construct a fresh request per method invocation
- Methods should accept `context.Context` and input parameters, assemble the `*http.Request` locally (or via a short-lived builder/helper created per call), then call `c.httpClient.Do(req)`
- If request-building logic is reused, factor it into unexported helper functions or a per-call builder type; never keep `http.Request` (URL params, body, headers) as fields on the long-lived client
- Ensure the underlying `*http.Client` is configured (timeouts, transport) and is safe for concurrent use; avoid mutating `Transport` after first use
- Always set headers on the request instance you’re sending, and close response bodies (`defer resp.Body.Close()`), handling errors appropriately

## Performance Optimization

### Memory Management

- Minimize allocations in hot paths
- Reuse objects when possible (consider `sync.Pool`)
- Use value receivers for small structs
- Preallocate slices when size is known
- Avoid unnecessary string conversions

### I/O: Readers and Buffers

- Most `io.Reader` streams are consumable once; reading advances state. Do not assume a reader can be re-read without special handling
- If you must read data multiple times, buffer it once and recreate readers on demand:
  - Use `io.ReadAll` (or a limited read) to obtain `[]byte`, then create fresh readers via `bytes.NewReader(buf)` or `bytes.NewBuffer(buf)` for each reuse
  - For strings, use `strings.NewReader(s)`; you can `Seek(0, io.SeekStart)` on `*bytes.Reader` to rewind
- For HTTP requests, do not reuse a consumed `req.Body`. Instead:
  - Keep the original payload as `[]byte` and set `req.Body = io.NopCloser(bytes.NewReader(buf))` before each send
  - Prefer configuring `req.GetBody` so the transport can recreate the body for redirects/retries: `req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf)), nil }`
- To duplicate a stream while reading, use `io.TeeReader` (copy to a buffer while passing through) or write to multiple sinks with `io.MultiWriter`
- Reusing buffered readers: call `(*bufio.Reader).Reset(r)` to attach to a new underlying reader; do not expect it to “rewind” unless the source supports seeking
- For large payloads, avoid unbounded buffering; consider streaming, `io.LimitReader`, or on-disk temporary storage to control memory

- Use `io.Pipe` to stream without buffering the whole payload:
  - Write to `*io.PipeWriter` in a separate goroutine while the reader consumes
  - Always close the writer; use `CloseWithError(err)` on failures
  - `io.Pipe` is for streaming, not rewinding or making readers reusable

- **Warning:** When using `io.Pipe` (especially with multipart writers), all writes must be performed in strict, sequential order. Do not write concurrently or out of order—multipart boundaries and chunk order must be preserved. Out-of-order or parallel writes can corrupt the stream and result in errors.

- Streaming multipart/form-data with `io.Pipe`:
  - `pr, pw := io.Pipe()`; `mw := multipart.NewWriter(pw)`; use `pr` as the HTTP request body
  - Set `Content-Type` to `mw.FormDataContentType()`
  - In a goroutine: write all parts to `mw` in the correct order; on error `pw.CloseWithError(err)`; on success `mw.Close()` then `pw.Close()`
  - Do not store request/in-flight form state on a long-lived client; build per call
  - Streamed bodies are not rewindable; for retries/redirects, buffer small payloads or provide `GetBody`

### Profiling

- Use built-in profiling tools (`pprof`)
- Benchmark critical code paths
- Profile before optimizing
- Focus on algorithmic improvements first
- Consider using `testing.B` for benchmarks

## Testing

### Test Organization

- Keep tests in the same package (white-box testing)
- Use `_test` package suffix for black-box testing
- Name test files with `_test.go` suffix
- Place test files next to the code they test

### Writing Tests

- Use table-driven tests for multiple test cases
- Name tests descriptively using `Test_functionName_scenario`
- Use subtests with `t.Run` for better organization
- Test both success and error cases
- Consider using `testify` or similar libraries when they add value, but don't over-complicate simple tests

### Test Naming and Organization

- Use descriptive subtest names: `t.Run("descriptive_scenario", ...)`
- Name should describe what is being tested and the expected outcome
- Use underscores for readability in test names (e.g., `with_custom_headers`, `invalid_ip_fails`)
- Group related tests together in the same test function using subtests
- Order tests logically: happy path first, then edge cases, then error cases

### Test Coverage

- Before adding tests, check current coverage: `go test -coverprofile=coverage.out`
- Identify gaps: `go tool cover -func=coverage.out | grep <filename>`
- Focus on untested or low-coverage functions first
- Verify coverage improvement after adding tests
- Aim for high coverage but focus on meaningful tests, not just coverage numbers
- Test both success and failure paths
- Include edge cases: nil values, empty inputs, boundary conditions

### Mock Objects

- Create minimal mock implementations for interfaces
- Place mocks at the bottom of test files
- Document what the mock is simulating
- Keep mocks simple and focused on the test scenario
- Implement only the methods needed for the test
- Use struct fields to control mock behavior (return values, errors)

### Test Helpers

- Mark helper functions with `t.Helper()`
- Create test fixtures for complex setup
- Use `testing.TB` interface for functions used in tests and benchmarks
- Clean up resources using `t.Cleanup()`

## Security Best Practices

### Input Validation

- Validate all external input
- Use strong typing to prevent invalid states
- Sanitize data before using in SQL queries
- Be careful with file paths from user input
- Validate and escape data for different contexts (HTML, SQL, shell)

### Cryptography

- Use standard library crypto packages
- Don't implement your own cryptography
- Use crypto/rand for random number generation
- Store passwords using bcrypt, scrypt, or argon2 (consider golang.org/x/crypto for additional options)
- Use TLS for network communication

## Documentation

### Code Documentation

- Prioritize self-documenting code through clear naming and structure
- Document all exported symbols with clear, concise explanations
- Start documentation with the symbol name
- Write documentation in English by default
- Use examples in documentation when helpful
- Keep documentation close to code
- Update documentation when code changes
- Avoid emoji in documentation and comments

### README and Documentation Files

- Include clear setup instructions
- Document dependencies and requirements
- Provide usage examples
- Document configuration options
- Include troubleshooting section

## Tools and Development Workflow

### Essential Tools

- `go fmt`: Format code
- `go vet`: Find suspicious constructs
- `golangci-lint`: Additional linting (golint is deprecated)
- `go test`: Run tests
- `go mod`: Manage dependencies
- `go generate`: Code generation

### Development Practices

- Run tests before committing
- Use pre-commit hooks for formatting and linting
- Keep commits focused and atomic
- Write meaningful commit messages
- Review diffs before committing

## Collections (Slices and Maps)

### Initialization

- Initialize maps with `make()` when you know they'll be populated: `make(map[string]Type)`
- For slices with known capacity: `make([]Type, 0, capacity)`
- Empty slices can be declared as `var slice []Type` (nil) or `[]Type{}` (non-nil empty)
- Nil slices and empty slices behave the same for most operations (len, cap, range)

### Iteration and Modification

- When filtering slices, preallocate with capacity: `result := make([]Type, 0, len(input))`
- Sort slices after building them if order matters: `slices.Sort()`
- Use `strings.ToLower()` for case-insensitive map keys
- Remove duplicates by using a map as a set, then converting back to slice

### Testing Collections

- Test nil vs empty collections
- Test single-element collections
- Test duplicate handling
- Test ordering (if relevant)

## Regular Expressions

### Pattern Compilation

- Always validate regex patterns at configuration time, not request time
- Use `regexp.MustCompile()` for patterns known at compile time
- Use `regexp.Compile()` for runtime patterns and handle errors
- Test both valid and invalid regex patterns
- Return clear error messages for invalid patterns

### Testing Regex Matchers

- Test exact matches and non-matches
- Test edge cases: empty strings, special characters
- Test multiple patterns (AND vs OR logic)
- Test include and exclude patterns separately and combined
- Document the expected matching behavior in test names

## Validation Patterns

### Configuration Validation

- Implement `Validate() error` methods for configuration structs
- Validate at initialization time, not at runtime
- Return specific errors with context: `fmt.Errorf("field %s: %w", fieldName, ErrInvalid)`
- Chain validations: validate dependencies after individual fields
- Use sentinel errors for common validation failures

### Request Validation

- Validate early: check required fields before processing
- Use sentinel errors for common validation failures
- Provide clear error messages indicating what's wrong and what's expected
- Example: `fmt.Errorf("%w: expected [header query cookie]; got: %s", ErrInvalidLocation, actual)`

### Testing Validation

- Test each validation rule independently
- Test combinations of valid/invalid fields
- Verify error messages are helpful
- Test that validation happens at the right time (config load vs request time)

## Configuration and Environment Variables

### Testing with goenvconf

- When testing functions that use `goenvconf.GetEnvFunc`, pass `goenvconf.GetOSEnv` explicitly
- Test both nil and non-nil `getEnvFunc` parameters
- Use `goenvconf.NewEnvStringSliceValue()` for creating test configurations
- Test environment variable expansion if applicable

### Configuration Validation

- Test zero values: `IsZero()` methods
- Test equality: `Equal()` methods
- Test nil configurations
- Test empty vs nil distinctions
- Test invalid configurations return appropriate errors

## Context Usage

### When to Accept Context

- All functions that perform I/O should accept `context.Context` as first parameter
- Authentication/authorization functions should accept context
- Long-running operations should accept context
- Pass context through the call chain, don't create new contexts unless necessary

### Context in Tests

- Use `context.Background()` in tests unless testing context cancellation
- Test context cancellation for long-running operations
- Don't create contexts with timeouts in library code - let callers control that

## Common Pitfalls to Avoid

- Not checking errors
- Ignoring race conditions
- Creating goroutine leaks
- Not using defer for cleanup
- Modifying maps concurrently
- Not understanding nil interfaces vs nil pointers
- Forgetting to close resources (files, connections)
- Using global variables unnecessarily
- Over-using unconstrained types (e.g., `any`); prefer specific types or generic type parameters with constraints. If an unconstrained type is required, use `any` rather than `interface{}`
- Not considering the zero value of types
- **Creating duplicate `package` declarations** - this is a compile error; always check existing files before adding package declarations
- Assuming slices/maps are safe for concurrent access without synchronization
- Not testing error paths and edge cases
- Validating at request time instead of configuration time
