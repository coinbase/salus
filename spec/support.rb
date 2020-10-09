def remove_file(file_path)
  File.delete(file_path) if File.exist?(file_path)
end

def remove_runtime(report)
  runtime_key = 'running_time'
  report_json = JSON.parse(report)
  report_json.delete(runtime_key)
  report_json['scans'].each do |scanner, _|
    report_json['scans'][scanner].delete(runtime_key)
  end
  report_json
end
