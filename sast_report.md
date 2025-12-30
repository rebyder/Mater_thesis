### Technical AST Detection Plan for CWE-532: Insecure Logging of Sensitive Information

#### 1. Deconstruct the Taint-Flow

To effectively map the taint flow from untrusted entry points to dangerous execution sinks, we need to identify the following components:

- **Untrusted Entry Points**: These are the sources of user input that can be manipulated by an attacker. In the provided code, the untrusted entry point is:
  - `user_input` from `input("Enter patient ID: ")`

- **Tainted Data Propagation**: The tainted data flows from the untrusted entry point to the SQL query construction. The path is as follows:
  - `user_input` → `get_patient_record(patient_id)` → `query` (constructed using `patient_id`)

- **Dangerous Execution Sinks**: These are the points in the code where the tainted data is executed or logged in a way that could expose sensitive information. In the provided code, the dangerous execution sink is:
  - `cursor.execute(query)` (where the SQL query is executed)
  - `print(f"[DEBUG] Executing: {query}")` (where the SQL query is logged)

#### 2. Modern API Intelligence

In addition to the provided code, we should consider other modern Python database libraries and their potential vulnerabilities:

- **SQLAlchemy**: 
  - Sink: `session.execute(query)` or `session.query(Model).filter(...)`
  - Sanitizer: Use of `session.query(Model).filter_by(...)` or `session.execute(text(query))` with parameter binding.

- **Django ORM**: 
  - Sink: `Model.objects.raw(query)` or `Model.objects.filter(...)`
  - Sanitizer: Use of `Model.objects.get(id=patient_id)` or `Model.objects.filter(id=patient_id)`

- **asyncpg**: 
  - Sink: `connection.fetch(query)` or `connection.execute(query)`
  - Sanitizer: Use of parameterized queries like `connection.fetch("SELECT * FROM patients WHERE id=$1", patient_id)`

#### 3. Precision Mapping

To avoid compilation errors, we need to clearly distinguish between AST elements:

- **Untrusted Input**: 
  - `Name` node: `user_input`
  
- **Function Call**: 
  - `Call` node: `get_patient_record(patient_id)`
  
- **Query Construction**: 
  - `Name` node: `patient_id`
  - `Attribute` node: `query`
  
- **Execution Sink**: 
  - `Call` node: `cursor.execute(query)`
  
- **Logging Sink**: 
  - `Call` node: `print(f"[DEBUG] Executing: {query}")`

#### 4. Structural AST Details

The following structural details should be captured in the CodeQL query:

- **Source**: 
  - Identify `input()` calls that capture user input.
  
- **Sink**: 
  - Identify `execute()` calls on database cursors or ORM methods that execute queries.
  - Identify `print()` calls that log sensitive information.

- **Sanitizer**: 
  - Identify calls to sanitizing functions or methods that ensure safe handling of user input (e.g., parameterized queries).

#### 5. Modeling Pattern

To implement a modular configuration structure, we recommend the following:

- **Source Predicate**: 
  - Define a predicate that captures user input sources, e.g., `isUserInput(input_node)`.

- **Sink Predicate**: 
  - Define a predicate that captures dangerous execution sinks, e.g., `isDangerousExecution(call_node)`.

- **Sanitizer Predicate**: 
  - Define a predicate that captures sanitizing functions, e.g., `isSanitizer(call_node)`.

- **ConfigSig**: 
  - Implement a `ConfigSig` that tracks the flow of tainted data across function boundaries, allowing for global tracking of sensitive data.

### Example Configuration

```python
def isUserInput(node):
    return node is input()

def isDangerousExecution(node):
    return node is cursor.execute() or node is print()

def isSanitizer(node):
    return node is session.query() or node is Model.objects.get()

def ConfigSig(data):
    # Logic to track data flow across functions
    pass
```

This structured approach will help in writing a predictive CodeQL query that effectively identifies instances of CWE-532 in various contexts, ensuring that sensitive information is not logged insecurely.

### Technical AST Detection Plan for CWE-203: Information Exposure Through Sent Data

#### 1. Deconstructing the Taint-Flow

To effectively map the taint flow from untrusted entry points to dangerous execution sinks, we will identify the following components:

- **Untrusted Entry Points**: 
  - `request.form.get("student_id", "")` - This is where user input is received and is considered untrusted.

- **Taint Propagation**:
  - The `student_id` variable is directly concatenated into the SQL query string, which is a critical point of taint propagation.

- **Dangerous Execution Sinks**:
  - The `cursor.execute()` method is the sink where the tainted data is executed against the database.

#### 2. Modern API Intelligence

In addition to the provided code, we will consider other modern Python database libraries and their potential vulnerabilities:

- **Sinks**:
  - For **SQLAlchemy**: 
    - `session.execute()`
    - `session.query().filter()`
  - For **Django ORM**:
    - `Model.objects.raw()`
    - `Model.objects.filter()`
  - For **asyncpg**:
    - `connection.execute()`
    - `connection.fetch()`

- **Potential Sanitizers**:
  - Use of **prepared statements**: 
    - For example, `cursor.execute("SELECT * FROM students WHERE student_id = %s", (student_id,))` in the context of `pymysql`.
    - In **SQLAlchemy**, use `session.query(Student).filter(Student.student_id == student_id).all()`.
  - Type conversion functions: 
    - Calls to `int()` or `float()` to sanitize numeric inputs before using them in queries.

#### 3. Precision Mapping

To avoid compilation errors, we will clearly distinguish between AST elements:

- **AST Elements**:
  - `Call`: Represents function calls, e.g., `cursor.execute()`, `db.cursor()`.
  - `Name`: Represents variable names, e.g., `student_id`, `pin`.
  - `Attribute`: Represents object attributes, e.g., `request.form`, `session`.

#### 4. Structural AST Details

We will specify the structural details of the AST nodes involved in the taint flow:

- **Untrusted Input**:
  - `Attribute` node: `request.form`
  - `Call` node: `get()`
  - `Name` node: `student_id`

- **Tainted Data Usage**:
  - `Name` node: `student_id`
  - `Call` node: `cursor.execute()`
  - `String` node: SQL query string

#### 5. Modeling Pattern

To implement a modular configuration structure, we will define predicates for Sources, Sinks, and Sanitizers:

- **Source Predicate**:
  - Identify untrusted data sources:
    ```python
    def is_source(node):
        return isinstance(node, Call) and node.func == 'get' and isinstance(node.parent, Attribute) and node.parent.attr == 'form'
    ```

- **Sink Predicate**:
  - Identify dangerous execution sinks:
    ```python
    def is_sink(node):
        return isinstance(node, Call) and (node.func == 'execute' or node.func == 'fetch' or node.func == 'filter')
    ```

- **Sanitizer Predicate**:
  - Identify sanitization methods:
    ```python
    def is_sanitizer(node):
        return isinstance(node, Call) and (node.func == 'execute' and len(node.args) == 2 and isinstance(node.args[1], Tuple))
    ```

- **ConfigSig Implementation**:
  - Implement a global tracking mechanism to allow data tracking across multiple function boundaries:
    ```python
    def config_sig(data):
        # Track data flow across function calls
        pass
    ```

By following this structured approach, we can enhance the detection of information exposure vulnerabilities in Python applications, ensuring that we account for modern database libraries and their specific patterns of usage.

### Technical AST Detection Plan for CWE-89: SQL Injection

#### 1. Deconstruct the Taint-Flow

To effectively detect SQL injection vulnerabilities, we need to map the flow of untrusted data from entry points to execution sinks. The following steps outline this process:

- **Untrusted Entry Points**: Identify sources of untrusted data, such as:
  - `request.args` (query parameters)
  - `request.form` (form data)
  - `input()` (user input in CLI applications)

- **Taint Propagation**: Track how this untrusted data propagates through the application. This includes:
  - Assignments to variables (e.g., `ids = request.args.get("ids", "")`)
  - Passing through functions (e.g., `add_time_filter(sql, start, end)`)

- **Dangerous Execution Sinks**: Identify where the tainted data is used in SQL execution, such as:
  - Calls to `execute()`
  - Dynamic SQL string concatenation (e.g., `query = "SELECT * FROM table WHERE column = '" + user_input + "'"`)

#### 2. Modern API Intelligence

In addition to the provided code, consider the following modern Python database libraries and their potential sinks:

- **SQLAlchemy**:
  - Sinks: `session.execute()`, `session.query()`
  - Sanitizers: Use of `text()` for raw SQL queries, or ORM methods that automatically parameterize queries.

- **Django ORM**:
  - Sinks: `Model.objects.raw()`, `cursor.execute()`
  - Sanitizers: Use of Django's ORM methods (e.g., `filter()`, `get()`) that handle parameterization.

- **asyncpg**:
  - Sinks: `connection.execute()`, `connection.fetch()`
  - Sanitizers: Use of parameterized queries with `$1`, `$2`, etc.

#### 3. Precision Mapping

To avoid compilation errors, we need to clearly distinguish between AST elements. Here are the key elements to track:

- **Source**: 
  - `request.args` (Call to `get()`)
  - `request.form` (Call to `get()`)
  - `input()` (Call to `input()`)

- **Sink**:
  - `execute()` (Call to `execute()`)
  - `cursor.execute()` (Call to `execute()` on cursor)
  - `session.execute()` (Call to `execute()` on SQLAlchemy session)

- **Sanitizer**:
  - Calls to `int()` or `float()` for numeric inputs
  - Use of prepared statements or ORM methods that handle parameterization

#### 4. Use Structural AST Details

When modeling the AST, we need to specify the types of nodes involved:

- **Source Nodes**:
  - `Call` (e.g., `request.args.get("ids", "")`)
  - `Call` (e.g., `input()`)

- **Sink Nodes**:
  - `Call` (e.g., `cur.execute(query)`)
  - `Call` (e.g., `session.execute(query)`)

- **Sanitizer Nodes**:
  - `Call` (e.g., `int(page)`)
  - `Call` (e.g., `float(price)`)

#### 5. Modeling Pattern

To implement a modular configuration structure, we can define predicates for sources, sinks, and sanitizers. This will allow for global tracking of data across multiple function boundaries.

- **Source Predicate**:
  ```python
  def is_source(node):
      return isinstance(node, Call) and (
          node.func == "get" and isinstance(node.value, Attribute) and node.value.attr in ["args", "form"]
          or node.func == "input"
      )
  ```

- **Sink Predicate**:
  ```python
  def is_sink(node):
      return isinstance(node, Call) and (
          node.func == "execute" or node.func == "execute" and isinstance(node.value, Attribute) and node.value.attr in ["cursor", "session"]
      )
  ```

- **Sanitizer Predicate**:
  ```python
  def is_sanitizer(node):
      return isinstance(node, Call) and (
          node.func in ["int", "float"] or
          (isinstance(node.value, Attribute) and node.value.attr in ["filter", "get"])
      )
  ```

- **ConfigSig Implementation**:
  ```python
  def config_sig(source, sink, sanitizer):
      # Track the flow of data from source to sink, applying sanitizers as needed
      if is_source(source):
          # Mark as tainted
          tainted_data = source
      if is_sanitizer(sanitizer):
          # Clean the tainted data
          tainted_data = None
      if is_sink(sink) and tainted_data:
          # Report vulnerability
          report_vulnerability(tainted_data, sink)
  ```

This structured approach will enhance the detection of SQL injection vulnerabilities in Python applications, ensuring that we can identify and mitigate risks effectively.