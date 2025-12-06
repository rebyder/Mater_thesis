import python
import semmle.python.TaintTracking

class UserInput extends TaintTracking::Source {
  override predicate isSource() {
    this instanceof RequestForm or
    this instanceof RequestArgs or
    this instanceof RequestJson or
    this instanceof DatabaseQueryResult or
    this instanceof ExternalAPIResponse or
    this instanceof EnvironmentVariable
  }
}

class HTMLRenderingFunction extends TaintTracking::Sink {
  override predicate isSink() {
    this instanceof RenderTemplate or
    this instanceof SendResponse or
    this instanceof CustomHTMLReturnFunction or
    this instanceof VariableAssignmentToHTTPResponse or
    this instanceof WriteToFileOrLog
  }
}

class SanitizerFunction extends TaintTracking::Sanitizer {
  override predicate isSanitizer() {
    this instanceof HtmlEscape or
    this instanceof FlaskMarkup or
    this instanceof BleachClean or
    this instanceof CustomSanitizationFunction
  }
}

from UserInput source, HTMLRenderingFunction sink
where not sink.isSanitizedBy(source)
select sink, "Exposure of sensitive information due to improper handling of user input." 

class DatabaseQueryResult extends TaintTracking::Source {
  override predicate isSource() {
    exists(DataSource ds | ds.getQuery() = this)
  }
}

class RequestForm extends TaintTracking::Source {
  override predicate isSource() {
    this.getName() = "request.form"
  }
}

class RequestArgs extends TaintTracking::Source {
  override predicate isSource() {
    this.getName() = "request.args"
  }
}

class RequestJson extends TaintTracking::Source {
  override predicate isSource() {
    this.getName() = "request.json"
  }
}

class ExternalAPIResponse extends TaintTracking::Source {
  override predicate isSource() {
    this.getName() = "externalAPI"
  }
}

class EnvironmentVariable extends TaintTracking::Source {
  override predicate isSource() {
    this.getName() = "environmentVariable"
  }
}

class RenderTemplate extends TaintTracking::Sink {
  override predicate isSink() {
    this.getName() = "render_template"
  }
}

class SendResponse extends TaintTracking::Sink {
  override predicate isSink() {
    this.getName() = "send_response"
  }
}

class CustomHTMLReturnFunction extends TaintTracking::Sink {
  override predicate isSink() {
    this.getName() = "customHTMLReturn"
  }
}

class VariableAssignmentToHTTPResponse extends TaintTracking::Sink {
  override predicate isSink() {
    this.getName() = "variableAssignmentToHTTPResponse"
  }
}

class WriteToFileOrLog extends TaintTracking::Sink {
  override predicate isSink() {
    this.getName() = "writeToFileOrLog"
  }
}

class HtmlEscape extends TaintTracking::Sanitizer {
  override predicate isSanitizer() {
    this.getName() = "html.escape"
  }
}

class FlaskMarkup extends TaintTracking::Sanitizer {
  override predicate isSanitizer() {
    this.getName() = "flask.Markup"
  }
}

class BleachClean extends TaintTracking::Sanitizer {
  override predicate isSanitizer() {
    this.getName() = "bleach.clean"
  }
}

class CustomSanitizationFunction extends TaintTracking::Sanitizer {
  override predicate isSanitizer() {
    this.getName() = "customSanitizationFunction"
  }
}

from UserInput source, HTMLRenderingFunction sink
where not sink.isSanitizedBy(source)
select sink, "Exposure of sensitive information due to improper handling of user input."