require 'thread'
module Salus
  class ThreadSafe
  	def execute
  	  Mutex.new.synchronize do
  	    pwd = `pwd`
  		puts "\n\nThread block #{pwd}\n\n"
    	yield
  		pwd = `pwd`
  		puts "\n\nThread block #{pwd}\n\n"
      end
    end
  end
end