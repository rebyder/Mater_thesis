/**
 * @name SQL Injection Detection
 * @description Detects SQL injection vulnerabilities by tracking untrusted data flow in Python applications.
 * @kind path-problem
 * @id py/sql-injection
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import MyFlow::PathGraph

module MyConfig implements DataFlow::ConfigSig {
    // Define source predicate to identify untrusted data sources
    predicate isSource(DataFlow::Node source) { 
        exists(Call call | 
            call = source and 
            call.getCallee().getName() = "get" and 
            call.getArgument(0).(Attribute).getName() = "args"
        )
    }

    // Define sink predicate to identify potential SQL execution points
    predicate isSink(DataFlow::Node sink) { 
        exists(Call call | 
            call = sink and 
            call.getCallee().getName() in ["execute", "raw", "filter"] and 
            exists(Name name | name = call.getCallee() and name.getName() in ["cur", "session", "Model"])
        )
    }
}

module MyFlow = TaintTracking::Global<MyConfig>;

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on a user-provided value: $@", source.getNode(), "Source Label"