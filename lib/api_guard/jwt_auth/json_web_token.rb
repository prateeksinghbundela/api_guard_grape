# frozen_string_literal: true

require 'jwt'
require 'api_guard/jwt_auth/refresh_jwt_token'
module ApiGuard
  module JwtAuth
    # Common module for JWT operations
    module JsonWebToken

      def self.current_time
        @current_time ||= Time.now.utc
      end

      def self.token_expire_at
        @token_expire_at ||= (current_time + ApiGuard.token_validity).to_i
      end

      def self.token_issued_at
        @token_issued_at ||= current_time.to_i
      end

      # Encode the payload with the secret key and return the JWT token
      def self.encode(payload)
        JWT.encode(payload, ApiGuard.token_signing_secret)
      end

      # Decode the JWT token and return the payload
      def self.decode(token, verify = true)
        HashWithIndifferentAccess.new(
          JWT.decode(token, ApiGuard.token_signing_secret, verify, verify_iat: true)[0]
        )
      end

      # Create a JWT token with resource detail in payload.
      # Also, create refresh token if enabled for the resource.
      #
      # This creates expired JWT token if the argument 'expired_token' is true which can be used for testing.
      def self.jwt_and_refresh_token(resource, resource_name, expired_token = false)
        payload = {
          "#{resource_name}_id": resource.id,
          exp: expired_token ? token_issued_at : token_expire_at,
          iat: token_issued_at
        }

        # Add custom data in the JWT token payload
        payload.merge!(resource.jwt_token_payload) if resource.respond_to?(:jwt_token_payload)
        [self.encode(payload), self.new_refresh_token(resource)]
      end

      # Create tokens and set response headers
      def self.create_token_and_set_header(resource, resource_name)
        access_token, refresh_token = jwt_and_refresh_token(resource, resource_name)
        set_token_headers(access_token, refresh_token)
      end

      # Set token details in response headers
      def self.set_token_headers(token, refresh_token = nil)
        response.headers['Access-Token'] = token
        response.headers['Refresh-Token'] = refresh_token if refresh_token
        response.headers['Expire-At'] = token_expire_at.to_s
      end

      # Set token issued at to current timestamp
      # to restrict access to old access(JWT) tokens
      def self.invalidate_old_jwt_tokens(resource)
        return unless ApiGuard.invalidate_old_tokens_on_password_change

        resource.token_issued_at = Time.at(token_issued_at).utc
      end

    #refresh token code=======================================

      def self.refresh_token_association(resource)
        resource.class.refresh_token_association
      end

      def self.refresh_token_enabled?(resource)
        refresh_token_association(resource).present?
      end

      def self.refresh_tokens_for(resource)
        refresh_token_association = refresh_token_association(resource)
        resource.send(refresh_token_association)
      end

      def self.find_refresh_token_of(resource, refresh_token)
        refresh_tokens_for(resource).find_by_token(refresh_token)
      end

      # Generate and return unique refresh token for the resource
      def self.uniq_refresh_token(resource)
        loop do
          random_token = SecureRandom.urlsafe_base64
          return random_token unless refresh_tokens_for(resource).exists?(token: random_token)
        end
      end

      # Create a new refresh_token for the current resource
      def self.new_refresh_token(resource)
        return unless refresh_token_enabled?(resource)

        refresh_tokens_for(resource).create(token: uniq_refresh_token(resource)).token
      end

      def self.destroy_all_refresh_tokens(resource)
        return unless refresh_token_enabled?(resource)

        refresh_tokens_for(resource).destroy_all
      end

    # blacklisted ======================================================
      def self.blacklisted_token_association(resource)
        resource.class.blacklisted_token_association
      end

      def self.token_blacklisting_enabled?(resource)
        blacklisted_token_association(resource).present?
      end

      def self.blacklisted_tokens_for(resource)
        blacklisted_token_association = blacklisted_token_association(resource)
        resource.send(blacklisted_token_association)
      end

      # Returns whether the JWT token is blacklisted or not
      def self.blacklisted?(resource)
        return false unless token_blacklisting_enabled?(resource)

        blacklisted_tokens_for(resource).exists?(token: @token)
      end

      # Blacklist the current JWT token from future access
      def self.blacklist_token

        return unless token_blacklisting_enabled?(current_resource)
        blacklisted_tokens_for(current_resource).create(token: @token, expire_at: Time.at(@decoded_token[:exp]).utc)
      end 


      def self.method_missing(name, *args)
        method_name = name.to_s

        if method_name.start_with?('authenticate_and_set_')
          resource_name = method_name.split('authenticate_and_set_')[1]
          authenticate_and_set_resource(resource_name)
        else
          super
        end
      end

      def self.respond_to_missing?(method_name, include_private = false)
        method_name.to_s.start_with?('authenticate_and_set_') || super
      end

      # Authenticate the JWT token and set resource
      def self.authenticate_and_set_resource(resource_name)
        @resource_name = resource_name

        @token = request.headers['Authorization']&.split('Bearer ')&.last
        return render_error(401, message: I18n.t('api_guard.access_token.missing')) unless @token

        authenticate_token

        # Render error response only if no resource found and no previous render happened
        render_error(401, message: I18n.t('api_guard.access_token.invalid')) if !current_resource && !performed?
      rescue JWT::DecodeError => e
        if e.message == 'Signature has expired'
          render_error(401, message: I18n.t('api_guard.access_token.expired'))
        else
          render_error(401, message: I18n.t('api_guard.access_token.invalid'))
        end
      end

      # Decode the JWT token
      # and don't verify token expiry for refresh token API request
      def self.decode_token
        # TODO: Set token refresh controller dynamic
        verify_token = (controller_name != 'tokens' || action_name != 'create')
        @decoded_token = decode(@token, verify_token)
      end

      # Returns whether the JWT token is issued after the last password change
      # Returns true if password hasn't changed by the user
      def self.valid_issued_at?(resource)
        return true unless ApiGuard.invalidate_old_tokens_on_password_change

        !resource.token_issued_at || @decoded_token[:iat] >= resource.token_issued_at.to_i
      end

      # Defines "current_{{resource_name}}" method and "@current_{{resource_name}}" instance variable
      # that returns "resource" value
      def self.define_current_resource_accessors(resource)
        define_singleton_method("current_#{@resource_name}") do
          instance_variable_get("@current_#{@resource_name}") ||
            instance_variable_set("@current_#{@resource_name}", resource)
        end
      end

      # Authenticate the resource with the '{{resource_name}}_id' in the decoded JWT token
      # and also, check for valid issued at time and not blacklisted
      #
      # Also, set "current_{{resource_name}}" method and "@current_{{resource_name}}" instance variable
      # for accessing the authenticated resource
      def self.authenticate_token
        return unless decode_token

        resource = find_resource_from_token(@resource_name.classify.constantize)

        if resource && valid_issued_at?(resource) && !blacklisted?(resource)
          define_current_resource_accessors(resource)
        else
          render_error(401, message: I18n.t('api_guard.access_token.invalid'))
        end
      end

      def self.find_resource_from_token(resource_class)
        resource_id = @decoded_token[:"#{@resource_name}_id"]
        return if resource_id.blank?

        resource_class.find_by(id: resource_id)
      end

      def self.current_resource
        return unless respond_to?("current_#{@resource_name}")

        public_send("current_#{@resource_name}")
      end
    end
  end
end
