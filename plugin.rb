# frozen_string_literal: true

# name: discourse-oauth2-basic
# about: Generic OAuth2 Plugin
# version: 0.3
# authors: Robin Ward
# url: https://github.com/discourse/discourse-oauth2-basic

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :oauth2_enabled

class ::OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"
  info do
    {
      id: access_token['id']
    }
  end

  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end
end

class OAuth2BasicAuthenticator < ::Auth::OAuth2Authenticator
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
                          token_url: SiteSetting.oauth2_token_url,
                          token_method: SiteSetting.oauth2_token_url_method.downcase.to_sym
                        }
                        opts[:authorize_options] = SiteSetting.oauth2_authorize_options.split("|").map(&:to_sym)

                        if SiteSetting.oauth2_send_auth_header?
                          opts[:token_params] = { headers: { 'Authorization' => basic_auth_header } }
                        end
                        unless SiteSetting.oauth2_scope.blank?
                          opts[:scope] = SiteSetting.oauth2_scope
                        end
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_client_id}:#{SiteSetting.oauth2_client_secret}")
  end

  def walk_path(fragment, segments)
    first_seg = segments[0]
    return if first_seg.blank? || fragment.blank?
    return nil unless fragment.is_a?(Hash) || fragment.is_a?(Array)
    if fragment.is_a?(Hash)
      deref = fragment[first_seg] || fragment[first_seg.to_sym]
    else
      deref = fragment[0] # Take just the first array for now, maybe later we can teach it to walk the array if we need to
    end

    return (deref.blank? || segments.size == 1) ? deref : walk_path(deref, segments[1..-1])
  end

  def json_walk(result, user_json, prop)
    path = SiteSetting.get("oauth2_json_#{prop}_path")
    if path.present?
      segments = path.split('.')
      val = walk_path(user_json, segments)
      result[prop] = val if val.present?
    end
  end

  def log(info)
    Rails.logger.warn("OAuth2 Debugging: #{info}") if SiteSetting.oauth2_debug_auth
  end

  def fetch_user_details(token, id)
    user_json_url = SiteSetting.oauth2_user_json_url.sub(':token', token.to_s).sub(':id', id.to_s)
    user_json_method = SiteSetting.oauth2_user_json_url_method

    log("user_json_url: #{user_json_method} #{user_json_url}")

    bearer_token = "Bearer #{token}"
    user_json_response =
      if user_json_method.downcase.to_sym == :post
        Net::HTTP
          .post_form(URI(user_json_url), 'Authorization' => bearer_token)
          .body
      else
        Excon.get(user_json_url, headers: { 'Authorization' => bearer_token, 'Accept' => 'application/json' }, expects: [200]).body
      end

    user_json = JSON.parse(user_json_response)

    log("user_json: #{user_json}")

    result = {}
    if user_json.present?
      json_walk(result, user_json, :user_id)
      json_walk(result, user_json, :username)
      json_walk(result, user_json, :name)
      json_walk(result, user_json, :email)
      json_walk(result, user_json, :avatar)
    end

    result
  end

  def after_authenticate(auth)
    log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")

    result = Auth::Result.new
    token = auth['credentials']['token']
    user_details = fetch_user_details(token, auth['info'][:id])

    result.name = user_details[:name]
    result.username = user_details[:username]
    result.email = user_details[:email]
    result.email_valid = result.email.present? && SiteSetting.oauth2_email_verified?
    avatar_url = user_details[:avatar]

    current_info = ::PluginStore.get("oauth2_basic", "oauth2_basic_user_#{user_details[:user_id]}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
      result.user&.update!(email: result.email) if SiteSetting.oauth2_overrides_email && result.email
    elsif SiteSetting.oauth2_email_verified?
      result.user = User.find_by_email(result.email)
      if result.user && user_details[:user_id]
        ::PluginStore.set("oauth2_basic", "oauth2_basic_user_#{user_details[:user_id]}", user_id: result.user.id)
      end
    end

    download_avatar(result.user, avatar_url)

    result.extra_data = { oauth2_basic_user_id: user_details[:user_id], avatar_url: avatar_url }
    result
  end

  def after_create_account(user, auth)
    ::PluginStore.set("oauth2_basic", "oauth2_basic_user_#{auth[:extra_data][:oauth2_basic_user_id]}", user_id: user.id)
    download_avatar(user, auth[:extra_data][:avatar_url])
  end

  def download_avatar(user, avatar_url)
    Jobs.enqueue(:download_avatar_from_url,
      url: avatar_url,
      user_id: user.id,
      override_gravatar: SiteSetting.sso_overrides_avatar
    ) if user && avatar_url.present?
  end

  def enabled?
    SiteSetting.oauth2_enabled
  end
end

auth_provider title_setting: "oauth2_button_title",
              enabled_setting: "oauth2_enabled",
              authenticator: OAuth2BasicAuthenticator.new('oauth2_basic'),
              message: "OAuth2",
              full_screen_login_setting: "oauth2_full_screen_login"

register_css <<CSS

  button.btn-social.oauth2_basic {
    background-color: #6d6d6d;
  }

CSS
