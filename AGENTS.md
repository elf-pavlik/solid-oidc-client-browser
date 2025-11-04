# AGENTS.md

## Build/Lint/Test Commands

- **Build**: `npm run build` (compiles TypeScript to ESM with type declarations)
- **Test**: `npm test` (runs all tests with coverage)
- **Run single test**: `npx jest path/to/test-file.test.ts`
- **Run single test suite**: `npx jest -t "suite name"`
- **Lint**: Uses TypeScript compiler for type checking (`tsc --noEmit`)

## Code Style Guidelines

### Imports
- Use ES module imports (`import x from 'module'`)
- Group imports in order: external libraries, internal modules, type-only imports
- Use absolute paths for internal modules when possible

### Formatting
- TypeScript with ESNext target
- ESM module format
- 2-space indentation
- Semicolons omitted
- Trailing commas in multi-line objects/arrays

### Types
- Use TypeScript with strict mode enabled
- Explicitly type all function parameters and return values
- Prefer interfaces over types for object shapes
- Use type-only imports (`import type { Type } from './module'`) when appropriate

### Naming Conventions
- Classes: PascalCase (`SessionCore`)
- Functions/variables: camelCase (`handleRedirectFromLogin`)
- Constants: UPPER_SNAKE_CASE (`DEFAULT_TIMEOUT`)
- Private members: prefixed with underscore (`_updateSessionDetailsFromToken`)
- Files: PascalCase for classes (`Session.ts`), camelCase for utilities

### Error Handling
- Use async/await with try/catch for promise-based operations
- Reject promises with Error objects containing descriptive messages
- Handle errors at appropriate levels rather than letting them bubble up unnecessarily
- Use specific error types when possible

### Testing
- Use Jest with TypeScript
- Mock external dependencies
- Test both success and failure cases
- Use descriptive test names that explain the expected behavior
- Group related tests in describe blocks