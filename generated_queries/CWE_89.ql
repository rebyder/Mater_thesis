```ql
/**
 * @kind path-problem
 * @id python/sql-injection
 * @name SQL Injection Detection
 * 
 * This query detects potential SQL injection vulnerabilities by tracking the flow of 
 * untrusted data from sources (like user input) to sinks (like SQL execution calls).
 * It uses taint tracking to identify where untrusted data is used in SQL queries 
 * without proper sanitization.
 */

import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import MyFlow::PathGraph

module MyConfig implements DataFlow::ConfigSig {
    // Predicate to identify sources of untrusted data
    predicate isSource(DataFlow::Node source) { 
        exists(DataFlow::Call call |
            call.getTarget().getName() = "get" and
            (call.getReceiver().(DataFlow::Attribute).getAttribute() = "args" or
             call.getReceiver().(DataFlow::Attribute).getAttribute() = "form") and
            call.getArgument(0).(DataFlow::StringLiteral) // Ensure it's a string literal
        ) or
        exists(DataFlow::Call inputCall |
            inputCall.getTarget().getName() = "input" // User input
        )
    }

    // Predicate to identify sinks where SQL execution occurs
    predicate isSink(DataFlow::Node sink) { 
        exists(DataFlow::Call executeCall |
            (executeCall.getTarget().getName() = "execute" and
             (executeCall.getReceiver().(DataFlow::Attribute).getAttribute() = "cursor" or
              executeCall.getReceiver().(DataFlow::Attribute).getAttribute() = "session"))
        )
    }
}

module MyFlow = TaintTracking::Global<MyConfig>;

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL Injection vulnerability from $@.", source.getNode(), "Source Label"
```