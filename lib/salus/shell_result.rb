module Salus
  class ShellResult
    attr_reader :stdout, :stderr, :status

    def initialize(stdout, stderr, process_status)
      @stdout = stdout
      @stderr = stderr
      @success = process_status.success?
      @status = process_status.exitstatus
    end

    def success?
      @success
    end
  end
end
