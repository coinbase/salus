# Useful for testing scanner objects.
def json_report
  JSON.parse(report.to_json)
end

def remove_file(file_path)
  File.delete(file_path) if File.exist?(file_path)
end
