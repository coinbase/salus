require_relative '../../../spec_helper.rb'

describe 'Bugsnag' do
  describe '#run' do
    context 'blank directory' do
      it 'bugsnag should receiev error' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::RepoNotEmpty.new(repository: repo, config: {})
        err_msg = 'Salus was run on a blank directory. This may indicate misconfiguration '\
                  'such as not correctly voluming in the repository to be scanned.'
        expect(scanner).to receive(:bugsnag_notify).with(err_msg)
        scanner.run
      end
    end
  end
end
