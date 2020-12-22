# frozen_string_literal: true

module ApiGuard
  module JwtAuth
    # Common module for refresh token functionality
    module RefreshJwtToken
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

      # authenticat-----------

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
