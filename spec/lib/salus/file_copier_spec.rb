require_relative '../../spec_helper.rb'

describe Salus::FileCopier do
  describe 'copy_files' do
    let(:copier) { Salus::FileCopier.new }
    let(:basedir) { 'spec/fixtures/file_copier/base' }
    let(:destdir) { 'spec/fixtures/file_copier/dest' }
    let(:b_source) { File.join(basedir, 'b.txt') }
    let(:b_dest) { File.join(destdir, 'b.txt') }

    it 'should ignore existing files' do
      expect(FileUtils).not_to receive(:cp)
      copier.copy_files(basedir, destdir, ['a.txt']) do |files|
        expect(files).to be_empty
      end
    end

    it 'should gracefully handle empty file list' do
      expect(FileUtils).not_to receive(:cp)
      copier.copy_files(basedir, destdir, []) do |files|
        expect(files).to be_empty
      end
    end

    it 'should copy files not present' do
      expect(FileUtils).to receive(:cp).with(b_source, b_dest)
      expect(File).to receive(:delete).with(b_dest)

      copier.copy_files(basedir, destdir, ['a.txt', 'b.txt']) do |files|
        expect(files).to eq([b_dest])
      end
    end

    it 'should clean up after itself' do
      expect(File.exist?(b_dest)).to be false
      expect(FileUtils).to receive(:cp).with(b_source, b_dest).and_call_original
      copier.copy_files(basedir, destdir, ['b.txt']) do |files|
        expect(files).to eq([b_dest])
        expect(File.exist?(b_dest)).to be true
      end

      expect(File.exist?(b_dest)).to be false
    end
    # rubocop:disable Lint/SuppressedException
    it 'should attempt to clean up when exceptions are thrown' do
      expect(File.exist?(b_dest)).to be false
      expect(FileUtils).to receive(:cp).with(b_source, b_dest).and_call_original
      begin
        copier.copy_files(basedir, destdir, ['b.txt']) do |files|
          expect(files).to eq([b_dest])
          expect(File.exist?(b_dest)).to be true
          raise 'foobar'
        end
      rescue StandardError
      end
      expect(File.exist?(b_dest)).to be false
    end
    # rubocop:enable Lint/SuppressedException
  end
end
