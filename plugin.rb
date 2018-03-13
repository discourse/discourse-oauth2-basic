# name: discourse-oauth2-basic
# about: Generic OAuth2 Plugin
# version: 0.2
# authors: Robin Ward
# url: https://github.com/discourse/discourse-oauth2-basic

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :oauth2_enabled

class ::OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"

  uid {
    raw_info[:user_id]
  }

  info do
    {
      username: raw_info[:username],
      email: raw_info[:email],
      name: raw_info[:name],
      access_token: access_token.token,
      refresh_token: access_token.refresh_token
    }
  end

  extra do
    {
      raw_info: raw_info
    }
  end

  def walk_path(fragment, segments)
    first_seg = segments[0]
    return if first_seg.blank? || fragment.blank?
    return nil unless fragment.is_a?(Hash)
    deref = fragment[first_seg] || fragment[first_seg.to_sym]

    return (deref.blank? || segments.size == 1) ? deref : walk_path(deref, segments[1..-1])
  end

  def json_walk(result, user_json, prop)
    path = SiteSetting.send("oauth2_json_#{prop}_path")
    if path.present?
      segments = path.split('.')
      val = walk_path(user_json, segments)
      result[prop] = val if val.present?
    end
  end

  def raw_info
    @raw_info ||= begin
      token = credentials["token"].to_s
      id = access_token["id"].to_s
      user_json_url = SiteSetting.oauth2_user_json_url.sub(':token', token).sub(':id', id)

      OAuth2BasicAuthenticator.log("user_json_url: #{user_json_url}")

      user_json = JSON.parse(open(user_json_url, 'Authorization' => "Bearer #{token}").read)

      OAuth2BasicAuthenticator.log("user_json: #{user_json}")

      result = {}
      if user_json.present?
        json_walk(result, user_json, :user_id)
        json_walk(result, user_json, :username)
        json_walk(result, user_json, :name)
        json_walk(result, user_json, :email)
      end

      result
    end
  end

  def callback_url
    full_host + script_name + callback_path
  end
end

class OAuth2BasicAuthenticator < ::Auth::OAuth2Authenticator

  def self.log(info)
    Rails.logger.warn("OAuth2 Debugging: #{info}") if SiteSetting.oauth2_debug_auth
  end

  def register_middleware(omniauth)
    omniauth.provider :oauth2_basic,
                      name: 'oauth2_basic',
                      setup: lambda { |env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.oauth2_client_id
                        opts[:client_secret] = SiteSetting.oauth2_client_secret
                        opts[:provider_ignores_state] = false
                        opts[:client_options] = {
                          authorize_url: SiteSetting.oauth2_authorize_url,
                          token_url: SiteSetting.oauth2_token_url
                        }
                        opts[:authorize_options] = SiteSetting.oauth2_authorize_options.split("|").map(&:to_sym)

                        if SiteSetting.oauth2_send_auth_header?
                          opts[:token_params] = { headers: { 'Authorization' => basic_auth_header } }
                        end
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_client_id}:#{SiteSetting.oauth2_client_secret}")
  end

  def after_authenticate(auth)
    OAuth2BasicAuthenticator.log("after_authenticate response: \n\ncreds: #{auth[:credentials]}\ninfo: #{auth[:info]}\nextra: #{auth[:extra]}")
    @opts[:trusted] = SiteSetting.oauth2_email_verified?
    super(auth)
  end

end

auth_provider title_setting: "oauth2_button_title",
              enabled_setting: "oauth2_enabled",
              authenticator: OAuth2BasicAuthenticator.new('oauth2_basic'),
              message: "OAuth2"

register_css <<CSS

  button.btn-social.oauth2_basic {
    background-color: #6d6d6d;
  }

CSS
