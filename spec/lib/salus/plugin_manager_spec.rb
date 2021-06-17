require_relative '../../spec_helper.rb'

describe Salus::PluginManager do
  describe 'apply_filter' do
    let(:filter) { Object.new }
    before(:each) do
      def filter.say_hello(subject)
        "hello #{subject}"
      end
    end

    it 'applies the filter' do
      Salus::PluginManager.register_filter('test-filters', filter)
      data = Salus::PluginManager.apply_filter('test-filters', :say_hello, 'foobar')
      expect(data).to eq('hello foobar')
    end

    it 'does not apply filter from a different context' do
      Salus::PluginManager.register_filter('test-filters', filter)
      data = Salus::PluginManager.apply_filter('test', :say_hello, 'foobar')
      expect(data).to eq('foobar')
    end
  end

  describe 'send_event' do
    let(:listener) { Object.new }
    before(:each) do
      def listener.myevent(data)
        data
      end
    end

    it 'sends the event' do
      Salus::PluginManager.register_listener(listener)
      expect(listener).to receive(:myevent).with('foo')
      Salus::PluginManager.send_event('myevent', "foo")
    end
  end
end
