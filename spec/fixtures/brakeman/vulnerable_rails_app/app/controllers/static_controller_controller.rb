class StaticControllerController < ApplicationController
  def index
    eval(params[:evil])
  end
end
