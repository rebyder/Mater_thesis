### Technical AST Detection Plan for SQL Injection Vulnerabilities (CWE-89)

#### 1. Deconstruct the Taint-Flow

To effectively identify SQL injection vulnerabilities, we need to map the flow of untrusted data from entry points (sources) to execution points (sinks). The following steps outline this process:

- **Sources**: Identify entry points where user input is received. Common sources include:
  - `request.args.get(...)` for query parameters
  - `request.form.get(...)` for form data
  - `input()` for console input

- **Taint Propagation**: Track how the data flows through the application. This includes:
  - Assignments to variables (e.g., `dataset = request.args.get(...)`)
  - Passing through functions (e.g., `add_time_filter(sql, start, end)`)

- **Sinks**: Identify dangerous execution points where SQL queries are executed. Common sinks include:
  - `cur.execute(...)` for executing SQL commands
  - ORM methods like `session.query(...)` in SQLAlchemy
  - `Model.objects.filter(...)` in Django ORM
  - `asyncpg.Connection.execute(...)` in asyncpg

#### 2. Modern API Intelligence

In addition to the provided code, consider the following modern Python database libraries and their potential sinks:

- **SQLAlchemy**:
  - Sinks: `session.execute(...)`, `session.query(...)`
  - Sanitizers: Use of `bindparam(...)` for parameterized queries.

- **Django ORM**:
  - Sinks: `Model.objects.raw(...)`, `Model.objects.filter(...)`
  - Sanitizers: Use of `Q(...)` objects to build queries safely.

- **asyncpg**:
  - Sinks: `connection.execute(...)`
  - Sanitizers: Use of parameterized queries with `$1`, `$2`, etc.

#### 3. Precision Mapping

To avoid compilation errors, we need to clearly distinguish between different AST elements. Here’s how to map them:

- **Source Nodes**:
  - `Call` for function calls (e.g., `request.args.get(...)`)
  - `Attribute` for accessing attributes (e.g., `request.args`)

- **Tainted Variables**:
  - `Name` for variable assignments (e.g., `dataset`, `start`, `end`)

- **Sink Nodes**:
  - `Call` for executing SQL commands (e.g., `cur.execute(...)`, `session.execute(...)`)
  - `Attribute` for ORM methods (e.g., `Model.objects.filter(...)`)

#### 4. Structural AST Details

When constructing the CodeQL query, we need to specify the structural details of the AST:

- **Source Example**:
  - `Call` node: `request.args.get(...)`
  - `Name` node: `dataset`

- **Tainted Flow**:
  - `Name` node: `dataset` flows into a `Call` node: `cur.execute(...)`

- **Sink Example**:
  - `Call` node: `cur.execute(...)` or `session.execute(...)`

#### 5. Modeling Pattern

To implement a modular configuration structure, we can define predicates for sources, sinks, and sanitizers. This allows for global tracking of data across multiple function boundaries.

- **Source Predicate**:
  - Define a predicate that captures all sources of untrusted data:
    ```python
    def is_source(node):
        return isinstance(node, Call) and (
            node.func.id == 'get' and
            isinstance(node.func.value, Attribute) and
            node.func.value.attr == 'args'
        )
    ```

- **Sink Predicate**:
  - Define a predicate for SQL execution points:
    ```python
    def is_sink(node):
        return isinstance(node, Call) and (
            node.func.id in ['execute', 'raw', 'filter'] and
            isinstance(node.func.value, Name) and
            node.func.value.id in ['cur', 'session', 'Model']
        )
    ```

- **Sanitizer Predicate**:
  - Define a predicate for sanitization methods:
    ```python
    def is_sanitizer(node):
        return isinstance(node, Call) and (
            node.func.id in ['bindparam', 'Q'] or
            (node.func.id == 'execute' and 'parameterized' in node.args)
        )
    ```

- **ConfigSig Implementation**:
  - Implement a `ConfigSig` to track data flow across function boundaries:
    ```python
    def ConfigSig(data):
        # Logic to track data flow from sources to sinks
        pass
    ```

By following this structured approach, we can enhance the detection of SQL injection vulnerabilities in Python applications, ensuring that we capture a wide range of potential attack vectors while maintaining precision in our analysis.