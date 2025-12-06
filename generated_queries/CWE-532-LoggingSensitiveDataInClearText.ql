import python
import TaintTracking

class SensitiveDataSource extends TaintTracking::Source {
  override predicate isSource() {
    this instanceof FunctionCall and (
      this.getTarget().getName() = "get_patient_id" or
      this.getTarget().getName() = "get_user_credentials" or
      this.getTarget().getName() = "input" or
      this.getTarget().getName() = "request" or
      this.getTarget().getName() = "os.getenv" or
      this.getTarget().getName() = "open" and this.getArgument(0).getType().hasName("config")
    )
  }
}

class SensitiveDataSink extends TaintTracking::Sink {
  override predicate isSink() {
    this instanceof FunctionCall and (
      this.getTarget().getName() = "print" or
      this.getTarget().getName() = "logger.debug" or
      this.getTarget().getName() = "logger.info" or
      this.getTarget().getName() = "logger.error" or
      this.getTarget().getName() = "write" or
      this.getTarget().getName() = "send"
    )
  }
}

class Sanitizer extends TaintTracking::Sanitizer {
  override predicate isSanitizer() {
    this instanceof FunctionCall and (
      this.getTarget().getName() = "mask_sensitive_data" or
      this.getTarget().getName() = "sanitize_for_logging"
    )
  }
}

from SensitiveDataSource source, SensitiveDataSink sink
where
  source.getASource() = sink.getASink() and
  not exists(Sanitizer sanitizer | sanitizer.getASanitizer() = source.getASource())
select source, sink, "Logging sensitive data in clear text."