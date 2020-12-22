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
        debugger
        resource.class.blacklisted_token_association
      end

      def self.token_blacklisting_enabled?(resource)
        debugger
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

    end
  end
end
