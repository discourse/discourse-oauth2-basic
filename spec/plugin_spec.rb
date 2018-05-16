require 'rails_helper'
require 'json'

# This is ugly... but it works!
# Need to load plugin.rb to avoid:
#
# NameError:
#   uninitialized constant OAuth2BasicAuthenticator
#
# And need to mock various methods to avoid:
#
# NoMethodError:
#   undefined method `enabled_site_setting' for main:Object
#
# etc.

def enabled_site_setting(arg)
end

def auth_provider(arg)
end

def register_css(arg)
end

require_relative '../plugin.rb'

describe OAuth2BasicAuthenticator do
  context 'after_authenticate' do
    it 'finds user by email' do
      authenticator = OAuth2BasicAuthenticator.new('oauth2_basic')
      user = Fabricate(:user)
      authenticator.expects(:fetch_user_details).returns(email: user.email)
      SiteSetting.oauth2_email_verified = true
      auth = { 'credentials' => { 'token': 'token' },
               'info' => { id: 'id' },
               'extra' => {} }

      result = authenticator.after_authenticate(auth)

      expect(result.user).to eq(user)
    end
  end

  it 'can walk json' do
    authenticator = OAuth2BasicAuthenticator.new('oauth2_basic')
    json_string = '{"user":{"id":1234,"email":{"address":"test@example.com"}}}'
    SiteSetting.oauth2_json_email_path = 'user.email.address'
    result = authenticator.json_walk({}, JSON.parse(json_string), :email)

    expect(result).to eq "test@example.com"
  end

  it 'can walk json that contains an array' do
    authenticator = OAuth2BasicAuthenticator.new('oauth2_basic')
    json_string = '{"email":"test@example.com","identities":[{"user_id":"123456789","provider":"auth0","isSocial":false}]}'
    SiteSetting.oauth2_json_user_id_path = 'identities.[].user_id'
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq "123456789"
  end

  it 'can walk json and handle an empty array' do
    authenticator = OAuth2BasicAuthenticator.new('oauth2_basic')
    json_string = '{"email":"test@example.com","identities":[]}'
    SiteSetting.oauth2_json_user_id_path = 'identities.[].user_id'
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq nil
  end

end
