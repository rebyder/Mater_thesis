```ql
/**
 * @kind path-problem
 * @id python/insecure-logging-sensitive-info
 * @name Insecure Logging of Sensitive Information
 * 
 * This query detects insecure logging practices in Python code where sensitive information 
 * from untrusted sources is logged without proper sanitization.
 */

import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import MyFlow::PathGraph

module MyConfig implements DataFlow::ConfigSig {
    // Predicate to identify untrusted sources, such as user inputs
    predicate isSource(DataFlow::Node source) { 
        source.asExpr() instanceof Call
        and source.getCallee().getName() = "input"
    }

    // Predicate to identify dangerous execution points, such as logging
    predicate isSink(DataFlow::Node sink) { 
        sink.asExpr() instanceof Call
        and sink.getCallee().getName() = "print"
    }

    // Predicate to identify sanitization methods
    predicate isSanitized(DataFlow::Node input) {
        input.asExpr() instanceof Call
        and input.getCallee().getName() in ["str", "repr"]
    }

    // Define the flow configuration
    override predicate isSanitized(DataFlow::Node input) {
        isSanitized(input)
    }
}

module MyFlow = TaintTracking::Global<MyConfig>;

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
    and not MyFlow::isSanitized(source) // Ensure the source is not sanitized
select sink.getNode(), source, sink, "This sensitive data is logged as clear text.", source.getNode(), "Untrusted Input Source"
```