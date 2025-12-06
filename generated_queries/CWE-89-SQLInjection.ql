import python
import TaintTracking

class UserInput extends TaintTracking::Source {
  UserInput() {
    this = request.args or request.form or request.GET or request.POST or
           anyFunctionReturningUserControlledData()
  }
}

class SQLExecution extends TaintTracking::Sink {
  SQLExecution() {
    this = cur.execute() or cur.executemany() or db.execute() or
           session.execute() or anyORMMethodExecutingRawSQL()
  }
}

class Sanitizer extends TaintTracking::Sanitizer {
  Sanitizer() {
    this = parameterizedQuery() or escape_string() or anyORMMethodHandlingEscaping()
  }
}

from UserInput source, SQLExecution sink
where not Sanitizer.sanitizes(source, sink)
select sink, "Potential SQL Injection vulnerability"