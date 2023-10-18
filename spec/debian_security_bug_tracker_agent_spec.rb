require 'rails_helper'
require 'huginn_agent/spec_helper'

describe Agents::DebianSecurityBugTrackerAgent do
  before(:each) do
    @valid_options = Agents::DebianSecurityBugTrackerAgent.new.default_options
    @checker = Agents::DebianSecurityBugTrackerAgent.new(:name => "DebianSecurityBugTrackerAgent", :options => @valid_options)
    @checker.user = users(:bob)
    @checker.save!
  end

  pending "add specs here"
end
