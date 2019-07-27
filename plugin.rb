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

  uid do
    if path = SiteSetting.oauth2_callback_user_id_path.split('.')
      recurse(access_token, [*path]) if path.present?
    end
  end

  info do
    if paths = SiteSetting.oauth2_callback_user_info_paths.split('|')
      result = Hash.new
      paths.each do |p|
        segments = p.split(':')
        if segments.length == 2
          key = segments.first
          path = [*segments.last.split('.')]
          result[key] = recurse(access_token, path)
        end
      end
      result
    end
  end

  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end

  def recurse(obj, keys)
    return nil if !obj
    k = keys.shift
    result = obj.respond_to?(k) ? obj.send(k) : obj[k]
    keys.empty? ? result : recurse(result, keys)
  end
end

class OAuth2BasicAuthenticator < Auth::ManagedAuthenticator
  def name
    'oauth2_basic'
  end

  def can_revoke?
    SiteSetting.oauth2_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.oauth2_allow_association_change
  end

  def register_middleware(omniauth)
    omniauth.provider :oauth2_basic,
                      name: name,
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
    path = SiteSetting.public_send("oauth2_json_#{prop}_path")
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
    connection = Excon.new(
      user_json_url,
      headers: { 'Authorization' => bearer_token, 'Accept' => 'application/json' }
    )
    user_json_response = connection.request(method: user_json_method)

    log("user_json_response: #{user_json_response.inspect}")

    if user_json_response.status == 200
      user_json = JSON.parse(user_json_response.body)

      log("user_json: #{user_json}")

      result = {}
      if user_json.present?
        json_walk(result, user_json, :user_id)
        json_walk(result, user_json, :username)
        json_walk(result, user_json, :name)
        json_walk(result, user_json, :email)
        json_walk(result, user_json, :email_verified)
        json_walk(result, user_json, :avatar)
      end
      result
    else
      nil
    end
  end

  def primary_email_verified?(auth)
    auth['info']['email_verified'] ||
    SiteSetting.oauth2_email_verified
  end

  def always_update_user_email?
    SiteSetting.oauth2_overrides_email
  end

  def after_authenticate(auth, existing_account: nil)
    log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\nuid: #{auth['uid']}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")

    if SiteSetting.oauth2_fetch_user_details?
      if fetched_user_details = fetch_user_details(auth['credentials']['token'], auth['uid'])
        auth['uid'] = fetched_user_details[:user_id] if fetched_user_details[:user_id]
        auth['info']['nickname'] = fetched_user_details[:username] if fetched_user_details[:username]
        auth['info']['image'] = fetched_user_details[:avatar] if fetched_user_details[:avatar]
        ['name', 'email', 'email_verified'].each do |property|
          auth['info'][property] = fetched_user_details[property.to_sym] if fetched_user_details[property.to_sym]
        end
      else
        result = Auth::Result.new
        result.failed = true
        result.failed_reason = I18n.t("login.authenticator_error_fetch_user_details")
        return result
      end
    end

    super(auth, existing_account: existing_account)
  end

  def enabled?
    SiteSetting.oauth2_enabled
  end
end

auth_provider title_setting: "oauth2_button_title",
              authenticator: OAuth2BasicAuthenticator.new,
              message: "OAuth2",
              full_screen_login_setting: "oauth2_full_screen_login"

register_css <<CSS

  button.btn-social.oauth2_basic {
    background-color: #6d6d6d;
  }

CSS

load File.expand_path("../lib/validators/oauth2_basic/oauth2_fetch_user_details_validator.rb", __FILE__)
