class VulnerableController < ApplicationController
  def search_users
    name = params[:name]
    # VULNERABLE: Interpolating params into ActiveRecord query string (CWE-89)
    @users = User.where("name = '#{name}'")
    render json: @users
  end

  def run_diagnostic
    target = params[:target]
    # VULNERABLE: Backtick shell execution with untrusted input (CWE-78)
    output = `nslookup #{target}`
    render plain: output
  end

  def load_preferences
    user_yaml = params[:config_yaml]
    # VULNERABLE: Unsafe YAML.load allows arbitrary object instantiation and RCE (CWE-502)
    preferences = YAML.load(user_yaml)
    render json: preferences
  end
end
