require 'rails_helper'

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
end
