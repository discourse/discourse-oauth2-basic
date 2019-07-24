class MoveToManagedAuthenticator < ActiveRecord::Migration[5.2]
  def change
    ::PluginStoreRow.where(plugin_name: 'oauth2_basic').each do |record|
      provider_uid = record.key.split('_').last
      
      begin
        value_hash = JSON.parse(record.value)
        user_id = value_hash["user_id"]
      rescue JSON::ParserError
        nil
      end
      
      if provider_uid && user_id
        UserAssociatedAccount.create(
          provider_name: 'oauth2_basic',
          provider_uid: provider_uid,
          user_id: user_id
        )
      end
      
      record.destroy
    end
  end
end
