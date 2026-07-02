require 'json'
require 'net/http'
require 'uri'

module NivritSdk
  class NivritClient
    def initialize(base_url, token)
      @base_url = base_url.chomp('/')
      @token = token
    end

    def request(method, path, body = nil)
      uri = URI.parse("#{@base_url}#{path}")
      req = Net::HTTP.const_get(method.capitalize).new(uri)
      req['Authorization'] = "Bearer #{@token}"
      req['Content-Type'] = 'application/json'
      req.body = body.to_json if body
      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
        http.request(req)
      end
      unless res.is_a?(Net::HTTPSuccess)
        raise "Nivrit API error #{res.code}: #{res.body}"
      end
      JSON.parse(res.body) if res.body && !res.body.empty?
    end

    def get_me; request('get', '/users/me'); end
    def list_orgs; request('get', '/users/me/orgs'); end
    def list_my_projects; request('get', '/users/me/projects'); end
    def list_org_projects(org_id); request('get', "/orgs/#{URI.encode_www_form_component(org_id)}/projects"); end
    def list_environments(project_id); request('get', "/projects/#{URI.encode_www_form_component(project_id)}/environments"); end
    def list_secrets(project_id, environment_id)
      request('get', "/projects/#{URI.encode_www_form_component(project_id)}/secrets?environment_id=#{URI.encode_www_form_component(environment_id)}")
    end
    def get_secret(project_id, environment_id, key)
      request('get', "/projects/#{URI.encode_www_form_component(project_id)}/secrets/#{URI.encode_www_form_component(key)}?environment_id=#{URI.encode_www_form_component(environment_id)}")
    end
    def list_secret_versions(project_id, environment_id, key)
      request('get', "/projects/#{URI.encode_www_form_component(project_id)}/secrets/#{URI.encode_www_form_component(key)}/versions?environment_id=#{URI.encode_www_form_component(environment_id)}")
    end
    def restore_secret(project_id, environment_id, key, version)
      request('post', "/projects/#{URI.encode_www_form_component(project_id)}/secrets/#{URI.encode_www_form_component(key)}/restore", { 'environment_id' => environment_id, 'version' => version })
    end
    def list_folders(project_id, environment_id)
      request('get', "/projects/#{URI.encode_www_form_component(project_id)}/folders?environment_id=#{URI.encode_www_form_component(environment_id)}")
    end
    def create_folder(project_id, environment_id, name, path)
      request('post', "/projects/#{URI.encode_www_form_component(project_id)}/folders", { 'environment_id' => environment_id, 'name' => name, 'path' => path })
    end
    def delete_folder(project_id, folder_id)
      request('delete', "/projects/#{URI.encode_www_form_component(project_id)}/folders/#{URI.encode_www_form_component(folder_id)}")
    end
    def list_imports(project_id, environment_id)
      request('get', "/projects/#{URI.encode_www_form_component(project_id)}/imports?environment_id=#{URI.encode_www_form_component(environment_id)}")
    end
    def create_import(project_id, environment_id, source_environment_id, position = 0)
      request('post', "/projects/#{URI.encode_www_form_component(project_id)}/imports", { 'environment_id' => environment_id, 'source_environment_id' => source_environment_id, 'position' => position })
    end
    def delete_import(project_id, import_id)
      request('delete', "/projects/#{URI.encode_www_form_component(project_id)}/imports/#{URI.encode_www_form_component(import_id)}")
    end
    def list_tags(project_id)
      request('get', "/projects/#{URI.encode_www_form_component(project_id)}/tags")
    end
    def create_tag(project_id, name, color = '#888888')
      request('post', "/projects/#{URI.encode_www_form_component(project_id)}/tags", { 'name' => name, 'color' => color })
    end
    def delete_tag(project_id, tag_id)
      request('delete', "/projects/#{URI.encode_www_form_component(project_id)}/tags/#{URI.encode_www_form_component(tag_id)}")
    end
    def list_secret_tags(project_id, environment_id, key)
      request('get', "/projects/#{URI.encode_www_form_component(project_id)}/secrets/#{URI.encode_www_form_component(key)}/tags?environment_id=#{URI.encode_www_form_component(environment_id)}")
    end
    def tag_secret(project_id, environment_id, key, tag_id)
      request('post', "/projects/#{URI.encode_www_form_component(project_id)}/secrets/#{URI.encode_www_form_component(key)}/tags", { 'environment_id' => environment_id, 'tag_id' => tag_id })
    end
    def untag_secret(project_id, environment_id, key, tag_id)
      request('delete', "/projects/#{URI.encode_www_form_component(project_id)}/secrets/#{URI.encode_www_form_component(key)}/tags/#{URI.encode_www_form_component(tag_id)}?environment_id=#{URI.encode_www_form_component(environment_id)}")
    end
    def create_org(body); request('post', '/orgs', body); end
    def create_project(body); request('post', '/projects', body); end
    def create_environment(project_id, body); request('post', "/projects/#{URI.encode_www_form_component(project_id)}/environments", body); end
    def create_secret(project_id, body); request('post', "/projects/#{URI.encode_www_form_component(project_id)}/secrets", body); end
    def create_pat(body); request('post', '/auth/pat', body); end
  end
end
