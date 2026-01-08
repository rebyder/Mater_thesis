```ql
/**
 * @kind path-problem
 * @id python/sql-injection
 * @name SQL Injection Detection
 * @description This query detects potential SQL injection vulnerabilities by tracking the flow of untrusted data from user inputs to SQL execution points in Python applications.
 */

import python
import semmle.python.dataflow.new
import MyFlow::PathGraph

// Define the source predicate for user input
predicate is_source(Node node) {
    node instanceof Call && (
        node.getFunction().getName() = "get" || 
        node.getFunction().getName() = "post" || 
        node.getFunction().getName() = "input" || 
        node.getFunction().getName() = "args" || 
        node.getFunction().getName() = "form"
    )
}

// Define the sink predicate for SQL execution
predicate is_sink(Node node) {
    node instanceof Call && (
        node.getFunction().getName() = "execute" || 
        node.getFunction().getName() = "executemany" || 
        node.getFunction().getName() = "raw" || 
        node.getFunction().getName() = "session.execute" || 
        node.getFunction().getName() = "Model.objects.raw" || 
        node.getFunction().getName() = "cursor.mogrify"
    )
}

// Track the taint flow from sources to sinks
from source, sink
where is_source(source) and is_sink(sink) and DataFlow::localFlow(source, sink)
select sink, source,
  "Potential SQL injection vulnerability detected."
```