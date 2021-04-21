# frozen_string_literal: true

require 'rails_helper'

describe OAuth2BasicAuthenticator do
  context 'after_authenticate' do
    let(:user) { Fabricate(:user) }
    let(:authenticator) { OAuth2BasicAuthenticator.new }

    let(:auth) do
      OmniAuth::AuthHash.new('provider' => 'oauth2_basic',
                             'credentials' => { 'token': 'token' },
                             'uid' => '123456789',
                             'info' => { id: 'id' },
                             'extra' => {})
    end

    before(:each) do
      SiteSetting.oauth2_email_verified = true
    end

    it 'finds user by email' do
      authenticator.expects(:fetch_user_details).returns(email: user.email)
      result = authenticator.after_authenticate(auth)
      expect(result.user).to eq(user)
    end

    it 'updated user email if enabled' do
      authenticator.stubs(:fetch_user_details).returns(email: user.email, user_id: 'id')

      # Create association
      result = authenticator.after_authenticate(auth)
      expect(result.user).to eq(user)

      # Change user email on remote system
      old_email = user.email
      authenticator.stubs(:fetch_user_details).returns(email: "newemail@example.com", user_id: 'id')

      # Login again - no change
      result = authenticator.after_authenticate(auth)
      expect(result.user).to eq(user)
      expect(result.user.email).to eq(old_email)

      # Enable site setting
      SiteSetting.oauth2_overrides_email = true
      result = authenticator.after_authenticate(auth)
      expect(result.user).to eq(user)
      expect(result.user.email).to eq("newemail@example.com")
    end

    it 'validates user email if provider has verified' do
      SiteSetting.oauth2_email_verified = false
      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: true)
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(true)
    end

    it 'doesnt validate user email if provider hasnt verified' do
      SiteSetting.oauth2_email_verified = false
      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: nil)
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(false)
    end

    it 'doesnt affect the site setting' do
      SiteSetting.oauth2_email_verified = true
      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: false)
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(true)
    end

    it 'handles true/false strings from identity provider' do
      SiteSetting.oauth2_email_verified = false
      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: 'true')
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(true)

      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: 'false')
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(false)
    end

    context "fetch_user_details" do
      before(:each) do
        SiteSetting.oauth2_fetch_user_details = true
        SiteSetting.oauth2_user_json_url = "https://provider.com/user"
        SiteSetting.oauth2_user_json_url_method = 'GET'
        SiteSetting.oauth2_json_email_path = 'account.email'
      end

      let(:success_response) do
        {
          status: 200,
          body: '{"account":{"email":"newemail@example.com"}}'
        }
      end

      let (:fail_response) do
        {
          status: 403
        }
      end

      it "works" do
        stub_request(:get, SiteSetting.oauth2_user_json_url).to_return(success_response)
        result = authenticator.after_authenticate(auth)
        expect(result.email).to eq("newemail@example.com")

        SiteSetting.oauth2_user_json_url_method = 'POST'
        stub_request(:post, SiteSetting.oauth2_user_json_url).to_return(success_response)
        result = authenticator.after_authenticate(auth)
        expect(result.email).to eq("newemail@example.com")
      end

      it "returns an standardised result if the http request fails" do
        stub_request(:get, SiteSetting.oauth2_user_json_url).to_return(fail_response)
        result = authenticator.after_authenticate(auth)
        expect(result.failed).to eq(true)

        SiteSetting.oauth2_user_json_url_method = 'POST'
        stub_request(:post, SiteSetting.oauth2_user_json_url).to_return(fail_response)
        result = authenticator.after_authenticate(auth)
        expect(result.failed).to eq(true)
      end
    end

    context 'avatar downloading' do
      before do
        SiteSetting.queue_jobs = true
        SiteSetting.oauth2_fetch_user_details = true
        SiteSetting.oauth2_email_verified = true
      end

      let(:job_klass) { Jobs::DownloadAvatarFromUrl }

      before do
        png = Base64.decode64("R0lGODlhAQABALMAAAAAAIAAAACAAICAAAAAgIAAgACAgMDAwICAgP8AAAD/AP//AAAA//8A/wD//wBiZCH5BAEAAA8ALAAAAAABAAEAAAQC8EUAOw==")
        stub_request(:get, "http://avatar.example.com/avatar.png").to_return(body: png, headers: { "Content-Type" => "image/png" })
      end

      it 'enqueues a download_avatar_from_url job for existing user' do
        authenticator.expects(:fetch_user_details).returns(
          email: user.email,
          avatar: 'http://avatar.example.com/avatar.png'
        )
        expect {
          authenticator.after_authenticate(auth)
        }.to change { job_klass.jobs.count }.by(1)

        job_args = job_klass.jobs.last['args'].first

        expect(job_args['url']).to eq("http://avatar.example.com/avatar.png")
        expect(job_args['user_id']).to eq(user.id)
        expect(job_args['override_gravatar']).to eq(false)
      end

      it 'enqueues a download_avatar_from_url job for new user' do
        authenticator.expects(:fetch_user_details).returns(
          email: "unknown@user.com",
          avatar: 'http://avatar.example.com/avatar.png'
        )

        auth_result = nil
        expect {
          auth_result = authenticator.after_authenticate(auth)
        }.to change { job_klass.jobs.count }.by(0)

        expect {
          authenticator.after_create_account(user, auth_result.session_data)
        }.to change { job_klass.jobs.count }.by(1)

        job_args = job_klass.jobs.last['args'].first

        expect(job_args['url']).to eq("http://avatar.example.com/avatar.png")
        expect(job_args['user_id']).to eq(user.id)
        expect(job_args['override_gravatar']).to eq(false)
      end
    end

  end

  it 'can walk json' do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"user":{"id":1234,"email":{"address":"test@example.com"}}}'
    SiteSetting.oauth2_json_email_path = 'user.email.address'
    result = authenticator.json_walk({}, JSON.parse(json_string), :email)

    expect(result).to eq "test@example.com"
  end

  it 'allows keys containing dots, if wrapped in quotes' do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"www.example.com/uid": "myuid"}'
    SiteSetting.oauth2_json_user_id_path = '"www.example.com/uid"'
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq "myuid"
  end

  it 'allows keys containing dots, if escaped' do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"www.example.com/uid": "myuid"}'
    SiteSetting.oauth2_json_user_id_path = 'www\.example\.com/uid'
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq "myuid"
  end

  it 'allows keys containing literal backslashes, if escaped' do
    authenticator = OAuth2BasicAuthenticator.new
    # This 'single quoted heredoc' syntax means we don't have to escape backslashes in Ruby
    # What you see is exactly what the user would enter in the site settings
    json_string = <<~'_'.chomp
      {"www.example.com/uid\\": "myuid"}
    _
    SiteSetting.oauth2_json_user_id_path = <<~'_'.chomp
      www\.example\.com/uid\\
    _
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)
    expect(result).to eq "myuid"
  end

  it 'can walk json that contains an array' do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"email":"test@example.com","identities":[{"user_id":"123456789","provider":"auth0","isSocial":false}]}'
    SiteSetting.oauth2_json_user_id_path = 'identities.[].user_id'
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq "123456789"
  end

  it 'can walk json and handle an empty array' do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"email":"test@example.com","identities":[]}'
    SiteSetting.oauth2_json_user_id_path = 'identities.[].user_id'
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq nil
  end

  it 'can walk json and find values by index in an array' do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"emails":[{"value":"test@example.com"},{"value":"test2@example.com"}]}'
    SiteSetting.oauth2_json_email_path = 'emails[1].value'
    result = authenticator.json_walk({}, JSON.parse(json_string), :email)

    expect(result).to eq "test2@example.com"
  end

  it 'can walk json and download avatar' do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"user":{"avatar":"http://example.com/1.png"}}'
    SiteSetting.oauth2_json_avatar_path = 'user.avatar'
    result = authenticator.json_walk({}, JSON.parse(json_string), :avatar)

    expect(result).to eq 'http://example.com/1.png'
  end

  context 'token_callback' do
    let(:user) { Fabricate(:user) }
    let(:strategy) { OmniAuth::Strategies::Oauth2Basic.new({}) }
    let(:authenticator) { OAuth2BasicAuthenticator.new }

    let(:auth) do
      OmniAuth::AuthHash.new(
        'provider' => 'oauth2_basic',
        'credentials' => {
          'token' => 'token'
        },
        'uid' => 'e028b1b918853eca7fba208a9d7e9d29a6e93c57',
        'info' => {
          "name" => 'Sammy the Shark',
          "email" => 'sammy@digitalocean.com'
        },
        'extra' => {}
      )
    end

    let(:access_token) do
      { "params" =>
        { "info" =>
          {
            "name" => "Sammy the Shark",
            "email" => "sammy@digitalocean.com",
            "uuid" => "e028b1b918853eca7fba208a9d7e9d29a6e93c57"
          }
        }
      }
    end

    before(:each) do
      SiteSetting.oauth2_callback_user_id_path = 'params.info.uuid'
      SiteSetting.oauth2_callback_user_info_paths = 'name:params.info.name|email:params.info.email'
    end

    it 'can retrieve user id from access token callback' do
      strategy.stubs(:access_token).returns(access_token)
      expect(strategy.uid).to eq 'e028b1b918853eca7fba208a9d7e9d29a6e93c57'
    end

    it 'can retrive user properties from access token callback' do
      strategy.stubs(:access_token).returns(access_token)
      expect(strategy.info['name']).to eq 'Sammy the Shark'
      expect(strategy.info['email']).to eq 'sammy@digitalocean.com'
    end

    it 'does apply user properties from access token callback in after_authenticate' do
      SiteSetting.oauth2_fetch_user_details = true
      authenticator.stubs(:fetch_user_details).returns(email: 'sammy@digitalocean.com')
      result = authenticator.after_authenticate(auth)

      expect(result.extra_data[:uid]).to eq 'e028b1b918853eca7fba208a9d7e9d29a6e93c57'
      expect(result.name).to eq 'Sammy the Shark'
      expect(result.email).to eq 'sammy@digitalocean.com'
    end

    it 'does work if user details are not fetched' do
      SiteSetting.oauth2_fetch_user_details = false
      result = authenticator.after_authenticate(auth)

      expect(result.extra_data[:uid]).to eq 'e028b1b918853eca7fba208a9d7e9d29a6e93c57'
      expect(result.name).to eq 'Sammy the Shark'
      expect(result.email).to eq 'sammy@digitalocean.com'
    end
  end
end
