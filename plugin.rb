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

require 'faraday/logging/formatter'
class OAuth2FaradayFormatter < Faraday::Logging::Formatter
  def request(env)
    warn <<~LOG
      OAuth2 Debugging: request #{env.method.upcase} #{env.url.to_s}

      Headers: #{env.request_headers}

      Body: #{env[:body]}
    LOG
  end

  def response(env)
    warn <<~LOG
      OAuth2 Debugging: response status #{env.status}

      From #{env.method.upcase} #{env.url.to_s}

      Headers: #{env.response_headers}

      Body: #{env[:body]}
    LOG
  end
end

# You should use this register if you want to add custom paths to traverse the user details JSON.
# We'll store the value in the user associated account's extra attribute hash using the full path as the key.
DiscoursePluginRegistry.define_filtered_register :oauth2_basic_additional_json_paths

class ::OAuth2BasicAuthenticator < Auth::ManagedAuthenticator
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
                        opts[:provider_ignores_state] = SiteSetting.oauth2_disable_csrf
                        opts[:client_options] = {
                          authorize_url: SiteSetting.oauth2_authorize_url,
                          token_url: SiteSetting.oauth2_token_url,
                          token_method: SiteSetting.oauth2_token_url_method.downcase.to_sym
                        }
                        opts[:authorize_options] = SiteSetting.oauth2_authorize_options.split("|").map(&:to_sym)

                        if SiteSetting.oauth2_authorize_signup_url.present? &&
                            ActionDispatch::Request.new(env).params["signup"].present?
                          opts[:client_options][:authorize_url] = SiteSetting.oauth2_authorize_signup_url
                        end

                        if SiteSetting.oauth2_send_auth_header? && SiteSetting.oauth2_send_auth_body?
                          # For maximum compatibility we include both header and body auth by default
                          # This is a little unusual, and utilising multiple authentication methods
                          # is technically disallowed by the spec (RFC2749 Section 5.2)
                          opts[:client_options][:auth_scheme] = :request_body
                          opts[:token_params] = { headers: { 'Authorization' => basic_auth_header } }
                        elsif SiteSetting.oauth2_send_auth_header?
                          opts[:client_options][:auth_scheme] = :basic_auth
                        else
                          opts[:client_options][:auth_scheme] = :request_body
                        end

                        unless SiteSetting.oauth2_scope.blank?
                          opts[:scope] = SiteSetting.oauth2_scope
                        end

                        if SiteSetting.oauth2_debug_auth && defined? OAuth2FaradayFormatter
                          opts[:client_options][:connection_build] = lambda { |builder|
                            builder.response :logger, Rails.logger, { bodies: true, formatter: OAuth2FaradayFormatter }

                            # Default stack:
                            builder.request :url_encoded             # form-encode POST params
                            builder.adapter Faraday.default_adapter  # make requests with Net::HTTP
                          }
                        end
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_client_id}:#{SiteSetting.oauth2_client_secret}")
  end

  def walk_path(fragment, segments, seg_index = 0)
    first_seg = segments[seg_index]
    return if first_seg.blank? || fragment.blank?
    return nil unless fragment.is_a?(Hash) || fragment.is_a?(Array)
    first_seg = segments[seg_index].scan(/([\d+])/).length > 0 ? first_seg.split("[")[0] : first_seg
    if fragment.is_a?(Hash)
      deref = fragment[first_seg] || fragment[first_seg.to_sym]
    else
      array_index = 0
      if (seg_index > 0)
        last_index = segments[seg_index - 1].scan(/([\d+])/).flatten() || [0]
        array_index = last_index.length > 0 ? last_index[0].to_i : 0
      end
      if fragment.any? && fragment.length >= array_index - 1
        deref = fragment[array_index][first_seg]
      else
        deref = nil
      end
    end

    if (deref.blank? || seg_index == segments.size - 1)
      deref
    else
      seg_index += 1
      walk_path(deref, segments, seg_index)
    end
  end

  def json_walk(result, user_json, prop, custom_path: nil)
    path = custom_path || SiteSetting.public_send("oauth2_json_#{prop}_path")
    if path.present?
      #this.[].that is the same as this.that, allows for both this[0].that and this.[0].that path styles
      path = path.gsub(".[].", ".").gsub(".[", "[")
      segments = parse_segments(path)
      val = walk_path(user_json, segments)
      result[prop] = val if val.present?
    end
  end

  def parse_segments(path)
    segments = [+""]
    quoted = false
    escaped = false

    path.split("").each do |char|
      next_char_escaped = false
      if !escaped && (char == '"')
        quoted = !quoted
      elsif !escaped && !quoted && (char == '.')
        segments.append +""
      elsif !escaped && (char == '\\')
        next_char_escaped = true
      else
        segments.last << char
      end
      escaped = next_char_escaped
    end

    segments
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

        DiscoursePluginRegistry.oauth2_basic_additional_json_paths.each do |detail|
          prop = "extra:#{detail}"
          json_walk(result, user_json, prop, custom_path: detail)
        end
      end
      result
    else
      nil
    end
  end

  def primary_email_verified?(auth)
    return true if SiteSetting.oauth2_email_verified
    verified = auth['info']['email_verified']
    verified = true if verified == "true"
    verified = false if verified == "false"
    verified
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

        DiscoursePluginRegistry.oauth2_basic_additional_json_paths.each do |detail|
          auth['extra'][detail] = fetched_user_details["extra:#{detail}"]
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
              authenticator: OAuth2BasicAuthenticator.new

load File.expand_path("../lib/validators/oauth2_basic/oauth2_fetch_user_details_validator.rb", __FILE__)
