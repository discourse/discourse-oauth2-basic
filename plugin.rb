# name: discourse-oauth2-basic
# about: Generic OAuth2 Plugin
# version: 0.1
# authors: Robin Ward

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :oauth2_enabled

class OAuth2BasicAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :oauth2,
                      name: 'oauth2_basic',
                      setup: lambda {|env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.oauth2_client_id
                        opts[:client_secret] = SiteSetting.oauth2_client_secret
                        opts[:provider_ignores_state] = true
                        opts[:client_options] = {
                          authorize_url: SiteSetting.oauth2_authorize_url,
                          token_url: SiteSetting.oauth2_token_url
                        }
                        opts[:token_params] = {headers: {'Authorization' => basic_auth_header }}
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_client_id}:#{SiteSetting.oauth2_client_secret}")
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

  def fetch_user_details(token)
    user_json_url = SiteSetting.oauth2_user_json_url.sub(':token', token)
    user_json = JSON.parse(open(user_json_url, 'Authorization' => "Bearer #{token}" ).read)

    result = {}
    if user_json.present?
      json_walk(result, user_json, :user_id)
      json_walk(result, user_json, :username)
      json_walk(result, user_json, :name)
      json_walk(result, user_json, :email)
    end

    result
  end

  def after_authenticate(auth)
    result = Auth::Result.new
    token = auth['credentials']['token']
    user_details = fetch_user_details(token)

    result.name = user_details[:name]
    result.username = user_details[:username]
    result.email = user_details[:email]
    result.email_valid = result.email.present? && SiteSetting.oauth2_email_verified

    current_info = ::PluginStore.get("oauth2_basic", "oauth2_basic_user_#{user_details[:user_id]}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
    end
    result.extra_data = { oauth2_basic_user_id: user_details[:user_id] }
    result
  end

  def after_create_account(user, auth)
    ::PluginStore.set("oauth2_basic", "oauth2_basic_user_#{auth[:extra_data][:oauth2_basic_user_id]}", {user_id: user.id })
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
