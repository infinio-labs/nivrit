module NivritSdk
  class NivritSession
    attr_reader :client, :crypto, :user, :private_key

    def initialize(base_url, token, crypto)
      @client = NivritClient.new(base_url, token)
      @crypto = crypto
      @project_keys = {}
    end

    def authenticate(password)
      @user = @client.get_me
      @private_key = @crypto.decrypt_private_key(
        @user['encrypted_private_key'],
        @user['private_key_nonce'],
        password
      )
    end

    def list_projects(org_id)
      projects = @client.list_org_projects(org_id)
      memberships = @client.list_my_projects.each_with_object({}) { |m, h| h[m['project_id']] = m }
      projects.map { |p| p.merge('membership' => memberships[p['id']]) }
    end

    def get_project_key(membership)
      raise 'No membership for project' unless membership

      pid = membership['project_id']
      return @project_keys[pid] if @project_keys.key?(pid)

      key = @crypto.decapsulate_project_key(membership['encrypted_project_key'], @private_key)
      @project_keys[pid] = key
      key
    end

    def list_secrets(project_id, environment_id)
      secrets = @client.list_secrets(project_id, environment_id)
      membership = @client.list_my_projects.find { |m| m['project_id'] == project_id }
      project_key = get_project_key(membership)
      secrets.map do |s|
        s.merge(
          'value' => @crypto.decrypt_value(s['encrypted_value'], s['nonce'], project_key)
        )
      end
    end
  end
end
