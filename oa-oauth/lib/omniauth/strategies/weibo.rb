require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    #
    # Authenticate to Sina WeiBo via OAuth and retrieve basic
    # user information.
    #
    # Usage:
    #
    #    use OmniAuth::Strategies::Weibo, 'consumerkey', 'consumersecret'
    #
    class Weibo < OmniAuth::Strategies::OAuth
      # Initialize the middleware
      #
      # @option options [Boolean, true] :sign_in When true, use the "Sign in with Twitter" flow instead of the authorization flow.
      def initialize(app, consumer_key = nil, consumer_secret = nil, options = {}, &block)
        client_options = {
          :site => 'https://api.t.sina.com.cn'
        }

        options[:authorize_params] = {:force_login => 'true'} if options.delete(:force_login) == true
        client_options[:authorize_path] = '/oauth/authenticate' unless options[:sign_in] == false
        super(app, :weibo, consumer_key, consumer_secret, client_options, options)
      end

      def auth_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => @access_token.params[:user_id],
          'user_info' => user_info,
          'extra' => {'user_hash' => user_hash}
        })
      end

      def user_info
        user_hash = self.user_hash

        {
          'name' => user_hash['name'],  
		  'screenName' => user_hash['screen_name'],
          'location' => user_hash['location'],
          'description' => user_hash['description'],
          'profileImageUrl' => user_hash['profileImageUrl'],
          'url' => user_hash['url']
        }
      end

      def user_hash
        @user_hash ||= MultiJson.decode(@access_token.get('/1/account/verify_credentials.json').body)
      end
    end
  end
end
