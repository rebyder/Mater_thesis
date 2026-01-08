### Technical AST Detection Plan for CWE-89: SQL Injection

#### 1. Deconstruct the Taint-Flow

To effectively map the taint flow from untrusted entry points to dangerous execution sinks, we need to identify the following components:

- **Sources**: Points in the code where user input is received.
- **Sinks**: Points in the code where SQL queries are executed.
- **Sanitizers**: Functions or methods that validate or sanitize user input before it reaches the sink.

**Mapping Taint Flow:**

- **Sources**:
  - `request.args.get(...)` for query parameters.
  - `request.form.get(...)` for form data.
  - `input(...)` for command-line inputs.

- **Sinks**:
  - `cur.execute(...)` for executing SQL queries.
  - `cur.callproc(...)` for calling stored procedures.
  - Any method that directly executes SQL commands, such as `cur.copy_expert(...)`.

- **Sanitizers**:
  - Parameterized queries (e.g., using `?` or `%s` placeholders).
  - Input validation functions that check for allowed characters or patterns.

**Example Taint Flow**:
```plaintext
Source (request.args.get("ids")) -> Tainted Variable (ids) -> Sink (cur.execute(query))
```

#### 2. Modern API Intelligence

In addition to the provided code, consider the following modern Python database libraries and their potential sinks:

- **SQLAlchemy**:
  - Sinks: `session.execute(...)`, `session.query(...).all()`, `session.query(...).filter(...)`.
  - Sanitizers: Use of ORM features to prevent SQL injection by using query builders.

- **Django ORM**:
  - Sinks: `Model.objects.raw(...)`, `Model.objects.filter(...)`.
  - Sanitizers: Use of Django's built-in query methods that automatically escape inputs.

- **Peewee**:
  - Sinks: `Model.select(...)`, `Model.raw(...)`.
  - Sanitizers: Use of query builders that handle escaping.

**Potential Sanitizers**:
- Use of parameterized queries.
- Input validation functions that restrict input to expected formats (e.g., regex checks).

#### 3. Precision Mapping

To avoid compilation errors, we need to clearly distinguish between AST elements. Here are the key AST elements to focus on:

- **Function Calls**: Identify function calls that represent sources, sinks, and sanitizers.
- **Variable Assignments**: Track variable assignments to identify where tainted data is stored.
- **String Concatenation**: Identify instances where strings are concatenated to form SQL queries.

**Example AST Elements**:
```python
# Source
source_call = ast.Call(func=ast.Attribute(value=ast.Name(id='request', ctx=ast.Load()), attr='args', ctx=ast.Load()), args=[ast.Constant(value='ids')], keywords=[])

# Sink
sink_call = ast.Call(func=ast.Attribute(value=ast.Name(id='cur', ctx=ast.Load()), attr='execute', ctx=ast.Load()), args=[ast.Name(id='query', ctx=ast.Load())], keywords=[])

# Sanitizer
sanitizer_call = ast.Call(func=ast.Attribute(value=ast.Name(id='db', ctx=ast.Load()), attr='execute', ctx=ast.Load()), args=[ast.Constant(value='SELECT * FROM users WHERE id = %s')], keywords=[])
```

#### 4. Use Structural AST Details

Utilize the structural details of the AST to identify patterns of taint flow. For example, look for:

- **Function Definitions**: Identify functions that handle user input.
- **Return Statements**: Identify where data is returned to the caller.
- **Conditional Statements**: Identify branches that may lead to execution of tainted data.

**Example Structural Patterns**:
```python
# Function definition for a source
def student_login():
    student_id = request.form.get("student_id", "")
    # Tainted variable

# Function definition for a sink
def execute_query(query):
    cur.execute(query)  # Potential sink
```

#### 5. Modeling Pattern: Modular Configuration

To create a modular configuration structure, define predicates for sources, sinks, and sanitizers:

```python
# Source Predicate
def is_source(node):
    return isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Attribute) and node.func.attr in ['get', 'getlist']) or
        (isinstance(node.func, ast.Name) and node.func.id == 'input')
    )

# Sink Predicate
def is_sink(node):
    return isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Attribute) and node.func.attr in ['execute', 'callproc']) or
        (isinstance(node.func, ast.Name) and node.func.id in ['copy_expert'])
    )

# Sanitizer Predicate
def is_sanitizer(node):
    return isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Attribute) and node.func.attr in ['execute'] and '%s' in node.args[0].s) or
        (isinstance(node.func, ast.Name) and node.func.id in ['validate_input'])
    )
```

### Conclusion

This Technical AST Detection Plan provides a comprehensive approach to enhancing the detection of SQL injection vulnerabilities in Python applications. By deconstructing the taint flow, leveraging modern API intelligence, and utilizing precise AST mapping, we can create a robust CodeQL query that effectively identifies and mitigates SQL injection risks.

### Technical AST Detection Plan for CWE-532: Insecure Logging of Sensitive Information

#### 1. Deconstruct the Taint-Flow

To effectively map the taint flow from untrusted entry points to dangerous execution sinks, we need to identify the following components:

- **Untrusted Entry Points**: These are the sources of user input that can be manipulated by an attacker. In the provided code, the entry point is the `user_input` variable, which captures input from the user.

- **Tainted Data Propagation**: The tainted data (in this case, `patient_id`) is passed through the function and concatenated into a SQL query string. We need to track how this data flows through the function.

- **Dangerous Execution Sinks**: These are the points in the code where the tainted data is used in a way that can lead to security vulnerabilities. In this example, the dangerous sink is the `cursor.execute(query)` call, where the SQL query is executed.

**Taint Flow Mapping**:
- `user_input` (untrusted) → `get_patient_record(patient_id)` → `query` (tainted) → `cursor.execute(query)` (sink)

#### 2. Modern API Intelligence

In addition to the SQLite library used in the example, we should consider other modern Python database libraries that may also be vulnerable to CWE-532. Here are some common libraries and their potential sinks:

- **SQLAlchemy**: 
  - Sink: `session.execute(query)`
  - Sink: `session.query(Model).filter(condition).all()`

- **Django ORM**:
  - Sink: `Model.objects.raw(query)`
  - Sink: `Model.objects.filter(condition)`

- **Psycopg2** (PostgreSQL):
  - Sink: `cursor.execute(query)`

**Potential Sanitizers**:
- Use parameterized queries or prepared statements to sanitize inputs.
- Use ORM methods that automatically handle input sanitization (e.g., `filter()` in Django ORM).
- Implement input validation functions to ensure that inputs conform to expected formats.

#### 3. Precision Mapping

To avoid compilation errors and ensure precision in our CodeQL query, we need to clearly distinguish between AST elements. Here are the key AST elements to focus on:

- **Function Call Nodes**: Identify function calls that represent user input (e.g., `input()`) and database execution (e.g., `execute()`).
- **String Concatenation Nodes**: Identify where user input is concatenated into SQL queries.
- **Variable Assignment Nodes**: Track the assignment of user input to variables that are later used in SQL queries.

#### 4. Use Structural AST Details

To effectively capture the necessary elements in the AST, we can define the following structural details:

- **Source Node**: Identify the `input()` function call as the source of untrusted data.
- **Tainted Variable Node**: Track the variable that holds the tainted data (e.g., `patient_id`).
- **Sink Node**: Identify the `execute()` function call as the sink where the tainted data is used.

#### 5. Modeling Pattern: Modular Configuration

To create a modular configuration structure, we can define predicates for sources, sinks, and sanitizers as follows:

```python
def is_source(node):
    return isinstance(node, FunctionCall) and node.name == "input"

def is_sink(node):
    return isinstance(node, FunctionCall) and (
        node.name in ["execute", "session.execute", "Model.objects.raw"]
    )

def is_tainted_variable(node):
    return isinstance(node, Variable) and node.name == "patient_id"

def is_sanitizer(node):
    return isinstance(node, FunctionCall) and (
        node.name in ["execute", "filter", "raw"]
    )
```

### Summary

This Technical AST Detection Plan outlines a comprehensive approach to detecting insecure logging of sensitive information in Python applications. By deconstructing the taint flow, identifying modern API sinks, and providing a modular configuration for sources, sinks, and sanitizers, we can enhance the effectiveness of CodeQL queries in identifying vulnerabilities related to CWE-532.

### Technical AST Detection Plan for CWE-209: Information Exposure through an Error Message

#### 1. Deconstruct the Taint-Flow

To effectively map the taint flow from untrusted entry points to dangerous execution sinks, we need to identify the following components:

- **Sources**: Points where untrusted data enters the application.
- **Sinks**: Points where this untrusted data can lead to vulnerabilities, such as error messages being returned to the user.
- **Sanitizers**: Mechanisms that can be used to clean or validate the untrusted data before it reaches the sink.

**Source Identification**:
- `request.form.get("student_id", "")`: This is the entry point where user input is received. The `student_id` is untrusted data.

**Taint Flow**:
- The `student_id` is concatenated directly into the SQL query string, leading to a potential SQL injection vulnerability.
- The error message returned in the `except` block (`return f"Error: {exc}", 500`) exposes sensitive information about the internal state of the application.

**Sink Identification**:
- The execution of the SQL query (`cursor.execute(query, (pin,))`) is a dangerous sink as it can lead to SQL injection.
- The return statement in the exception block is another sink that exposes internal error messages.

#### 2. Modern API Intelligence

In addition to the provided code, we should consider other modern Python database libraries and their potential sinks:

- **SQLAlchemy**: Using raw SQL queries or improperly parameterized queries can lead to similar vulnerabilities.
- **Django ORM**: Directly using `raw()` queries without proper sanitization can expose the application to SQL injection.

**Potential Sinks**:
- `cursor.execute()`
- `db.session.execute()` (for SQLAlchemy)
- `Model.objects.raw()` (for Django ORM)

**Potential Sanitizers**:
- Use parameterized queries or prepared statements to prevent SQL injection.
- Implement input validation and sanitization functions to clean user inputs.

#### 3. Precision Mapping

To avoid compilation errors, we need to clearly distinguish between AST elements. Here’s how we can map the relevant components:

- **Source**: 
  - `request.form.get("student_id", "")` → `ASTNode: Call`
  
- **Sink**:
  - `cursor.execute(query, (pin,))` → `ASTNode: Call`
  - `return f"Error: {exc}", 500` → `ASTNode: Return`

- **Sanitizer**:
  - `parameterized_query_function(student_id)` → `ASTNode: Call`

#### 4. Use Structural AST Details

To create a robust CodeQL query, we need to focus on the structural details of the AST. Here’s how we can represent the components:

- **Source Node**:
  ```python
  source_node = Call(func=Attribute(value=Name(id='request'), attr='form'), args=[Constant(value='student_id'), Constant(value='')])
  ```

- **Sink Node**:
  ```python
  sink_node = Call(func=Attribute(value=Name(id='cursor'), attr='execute'), args=[BinaryOp(left=Constant(value="SELECT * FROM students WHERE student_id = '"), op=Add(), right=Name(id='student_id'))])
  ```

- **Sanitizer Node**:
  ```python
  sanitizer_node = Call(func=Name(id='parameterized_query_function'), args=[Name(id='student_id')])
  ```

#### 5. Modeling Pattern: Modular Configuration

To create a modular configuration structure, we can define predicates for sources, sinks, and sanitizers:

```python
def is_source(node):
    return isinstance(node, Call) and node.func == 'request.form.get'

def is_sink(node):
    return isinstance(node, Call) and node.func in ['cursor.execute', 'db.session.execute', 'Model.objects.raw']

def is_sanitizer(node):
    return isinstance(node, Call) and node.func == 'parameterized_query_function'
```

### Summary

This Technical AST Detection Plan outlines a comprehensive approach to detecting CWE-209 vulnerabilities in Python applications. By deconstructing the taint flow, identifying modern API sinks, and providing a modular configuration for sources, sinks, and sanitizers, we can enhance the predictive capabilities of CodeQL queries to effectively mitigate information exposure through error messages.