require 'open3'
require_relative '../spec_helper.rb'

# This tests for failure to run the Salus client inside our
# docker container. This could happen, if for example, we
# require an erronious package that exists on our local dev
# environment but not inside the docker container. Usually we
# run the new Salus build manually on some CircleCI projects
# to be sure - but this test should take care of that.

DOCKER_BUILD_COMMAND = 'docker build -t salus-test .'.freeze
DOCKER_RUN_COMMAND = 'docker run -e RUNNING_SALUS_TESTS=true -t '\
  '--rm -v $(pwd):/home/repo salus-test'.freeze

describe 'docker' do
  let(:report_file_path) { 'spec/fixtures/docker/reports/salus_report.json' }

  it 'should build the latest image, run successfully and output the '\
     'report to the correctly volumed location' do
    # cleanup from preivous test if last cleanup failed
    remove_file(report_file_path)

    stdout, stderr, exit_status = Open3.capture3(DOCKER_BUILD_COMMAND)
    expect(exit_status.success?).to eq(true), "STDOUT:\n#{stdout}\n\nSTDERR:\n#{stderr}"

    Dir.chdir('spec/fixtures/docker') do
      stdout, stderr, exit_status = Open3.capture3(DOCKER_RUN_COMMAND)
    end
    expect(exit_status.success?).to eq(true), "STDOUT:\n#{stdout}\n\nSTDERR:\n#{stderr}"
    expect(File.read(report_file_path)).to eq(
      File.read('spec/fixtures/docker/expected_report.json').strip
    )

    # remove report file that was generated from Salus execution
    remove_file(report_file_path)
  end
end
