const swaggerJSDoc = require('swagger-jsdoc');

const serverUrl = process.env.SWAGGER_SERVER_URL;

const options = {
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'Glossy_Gly-Kitchen API',
      version: '1.4.0',
      description: 'Production-ready food ordering backend API with auth, account-deletion OTP flow, admin, foods, cart, orders, payments, and disputes.',
    },
    servers: [
      {
        url: serverUrl,
      },
    ],
    tags: [
      { name: 'Auth' },
      { name: 'Admin' },
      { name: 'Payments' },
      { name: 'Foods' },
      { name: 'Cart' },
      { name: 'Orders' },
      { name: 'System' },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
        adminBearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
        AdminBootstrapKey: {
          type: 'apiKey',
          in: 'header',
          name: 'x-admin-bootstrap-key',
        },
      },
      schemas: {
        ErrorResponse: {
          type: 'object',
          properties: {
            error: { type: 'string' },
          },
        },
        MessageResponse: {
          type: 'object',
          properties: {
            message: { type: 'string' },
          },
        },
        SignupRequest: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            phone: { type: 'string' },
            password: { type: 'string', minLength: 8 },
            referralCode: { type: 'string' },
          },
        },
        VerifyRequest: {
          type: 'object',
          required: ['userId', 'otp'],
          properties: {
            userId: { type: 'string', format: 'uuid' },
            otp: { type: 'string' },
          },
        },
        LoginRequest: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string' },
            deviceId: { type: 'string' },
          },
        },
        LoginOtpRequest: {
          type: 'object',
          required: ['email', 'otp'],
          properties: {
            email: { type: 'string', format: 'email' },
            otp: { type: 'string' },
          },
        },
        RefreshTokenRequest: {
          type: 'object',
          required: ['refreshToken'],
          properties: {
            refreshToken: { type: 'string' },
          },
        },
        RequestLoginOtpRequest: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
          },
        },
        ForgotPasswordVerifyRequest: {
          type: 'object',
          required: ['email', 'otp'],
          properties: {
            email: { type: 'string', format: 'email' },
            otp: { type: 'string' },
          },
        },
        ForgotPasswordResetRequest: {
          type: 'object',
          required: ['resetToken', 'newPassword'],
          properties: {
            resetToken: { type: 'string' },
            newPassword: { type: 'string', minLength: 8 },
          },
        },
        ResendOtpRequest: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
          },
        },
        DeleteAccountRequest: {
          type: 'object',
          required: ['otp'],
          properties: {
            otp: { type: 'string', description: '6-digit OTP sent to your email' },
          },
        },
        AuthTokensResponse: {
          type: 'object',
          properties: {
            message: { type: 'string' },
            accessToken: { type: 'string' },
            refreshToken: { type: 'string' },
          },
        },
        FoodItem: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            name: { type: 'string' },
            price: { type: 'string' },
            description: { type: 'string' },
            category: { type: 'string' },
            available: { type: 'integer' },
          },
        },
        CreateFoodRequest: {
          type: 'object',
          required: ['name', 'price'],
          properties: {
            name: { type: 'string' },
            price: { type: 'number' },
            description: { type: 'string' },
            category: { type: 'string' },
          },
        },
        UpdateFoodRequest: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            price: { type: 'number' },
            description: { type: 'string' },
            category: { type: 'string' },
            available: { type: 'boolean' },
          },
        },
        CartMutationRequest: {
          type: 'object',
          required: ['foodId', 'quantity'],
          properties: {
            foodId: { type: 'string', format: 'uuid' },
            quantity: { type: 'integer', minimum: 0 },
          },
        },
        CartItem: {
          type: 'object',
          properties: {
            food_id: { type: 'string', format: 'uuid' },
            name: { type: 'string' },
            price: { type: 'string' },
            quantity: { type: 'integer' },
            subtotal: { type: 'string' },
            available: { type: 'integer' },
          },
        },
        CartResponse: {
          type: 'object',
          properties: {
            userId: { type: 'string', format: 'uuid' },
            items: {
              type: 'array',
              items: { $ref: '#/components/schemas/CartItem' },
            },
            total: { type: 'string' },
          },
        },
        CreateOrderResponse: {
          type: 'object',
          properties: {
            orderId: { type: 'string', format: 'uuid' },
            status: { type: 'string' },
            total: { type: 'string' },
          },
        },
        OrderItem: {
          type: 'object',
          properties: {
            food_id: { type: 'string', format: 'uuid' },
            quantity: { type: 'integer' },
            price_at_order: { type: 'string' },
            name: { type: 'string' },
          },
        },
        OrderResponse: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            user_id: { type: 'string', format: 'uuid' },
            status: { type: 'string' },
            total_amount: { type: 'string' },
            items: {
              type: 'array',
              items: { $ref: '#/components/schemas/OrderItem' },
            },
          },
        },
        PaymentCard: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            provider: { type: 'string', example: 'paystack' },
            last4: { type: 'string', example: '1234' },
            exp_month: { type: 'string', example: '09' },
            exp_year: { type: 'string', example: '2030' },
            card_type: { type: 'string', example: 'visa' },
            bank: { type: 'string', example: 'GTBank' },
            account_name: { type: 'string', example: 'John Doe' },
            is_default: { type: 'integer' },
            created_at: { type: 'string', format: 'date-time' },
            updated_at: { type: 'string', format: 'date-time' },
          },
        },
        UpdateOrderStatusRequest: {
          type: 'object',
          required: ['status'],
          properties: {
            status: {
              type: 'string',
              enum: ['pending', 'confirmed', 'preparing', 'out_for_delivery', 'completed', 'cancelled'],
            },
          },
        },
        UpdateOrderStatusResponse: {
          type: 'object',
          properties: {
            message: { type: 'string' },
            orderId: { type: 'string', format: 'uuid' },
            newStatus: { type: 'string' },
          },
        },
        HealthResponse: {
          type: 'object',
          properties: {
            status: { type: 'string' },
            timestamp: { type: 'string', format: 'date-time' },
          },
        },
        AdminLoginRequest: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string' },
            otp: { type: 'string', description: 'Required for new device or changed IP' },
            deviceId: { type: 'string', description: 'Stable client-generated device identifier' },
            deviceLabel: { type: 'string', description: 'Human-friendly device name' },
          },
        },
        AdminBootstrapRequest: {
          type: 'object',
          required: ['email', 'password', 'fullName'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string' },
            fullName: { type: 'string' },
            role: {
              type: 'string',
              enum: ['super_admin', 'operations_admin', 'support_admin'],
            },
          },
        },
        AdminUserStatusUpdateRequest: {
          type: 'object',
          properties: {
            verified: { type: 'boolean' },
            isSuspended: { type: 'boolean' },
          },
        },
        AdminCreateDisputeRequest: {
          type: 'object',
          required: ['title', 'description'],
          properties: {
            orderId: { type: 'string', format: 'uuid' },
            userId: { type: 'string', format: 'uuid' },
            title: { type: 'string' },
            description: { type: 'string' },
            priority: { type: 'string', enum: ['low', 'medium', 'high', 'urgent'] },
            category: { type: 'string' },
            assignedAdminId: { type: 'string', format: 'uuid' },
          },
        },
        AdminUpdateDisputeRequest: {
          type: 'object',
          properties: {
            status: { type: 'string', enum: ['open', 'investigating', 'resolved', 'rejected', 'closed'] },
            priority: { type: 'string', enum: ['low', 'medium', 'high', 'urgent'] },
            category: { type: 'string' },
            assignedAdminId: { type: 'string', format: 'uuid', nullable: true },
            resolutionNotes: { type: 'string' },
          },
        },
        AdminDisputeCommentRequest: {
          type: 'object',
          required: ['comment'],
          properties: {
            comment: { type: 'string' },
            isInternal: { type: 'boolean' },
          },
        },
      },
    },
    paths: {
      '/auth/signup': {
        post: {
          tags: ['Auth'],
          summary: 'Register a new user and send OTP',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SignupRequest' },
              },
            },
          },
          responses: {
            '201': {
              description: 'Created',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      message: { type: 'string' },
                      userId: { type: 'string', format: 'uuid' },
                    },
                  },
                },
              },
            },
            '400': { description: 'Bad request' },
            '409': { description: 'Conflict' },
          },
        },
      },
      '/auth/verify': {
        post: {
          tags: ['Auth'],
          summary: 'Verify OTP and issue tokens',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/VerifyRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthTokensResponse' },
                },
              },
            },
            '400': { description: 'Invalid or expired OTP' },
          },
        },
      },
      '/auth/resend-otp': {
        post: {
          tags: ['Auth'],
          summary: 'Resend OTP to email',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ResendOtpRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'OK' },
            '404': { description: 'User not found' },
          },
        },
      },
      '/auth/login': {
        post: {
          tags: ['Auth'],
          summary: 'Login with email and password',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/LoginRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthTokensResponse' },
                },
              },
            },
            '400': { description: 'Invalid credentials' },
            '403': { description: 'Not verified' },
            '404': { description: 'Not found' },
          },
        },
      },
      '/auth/request-login-otp': {
        post: {
          tags: ['Auth'],
          summary: 'Request OTP for login',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RequestLoginOtpRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'OTP request accepted' },
            '400': { description: 'Validation error' },
          },
        },
      },
      '/auth/login-otp': {
        post: {
          tags: ['Auth'],
          summary: 'Login with email and OTP',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/LoginOtpRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthTokensResponse' },
                },
              },
            },
          },
        },
      },
      '/auth/forgot-password/request': {
        post: {
          tags: ['Auth'],
          summary: 'Request password reset OTP',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RequestLoginOtpRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'Password reset OTP request accepted' },
            '400': { description: 'Validation error' },
            '503': { description: 'Password reset service unavailable (migration missing)' },
          },
        },
      },
      '/auth/forgot-password/verify': {
        post: {
          tags: ['Auth'],
          summary: 'Verify password reset OTP and issue short-lived reset token',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ForgotPasswordVerifyRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'OTP verified' },
            '400': { description: 'Invalid or expired OTP' },
            '429': { description: 'Too many invalid OTP attempts' },
            '503': { description: 'Password reset service unavailable (migration missing)' },
          },
        },
      },
      '/auth/forgot-password/reset': {
        post: {
          tags: ['Auth'],
          summary: 'Reset password using reset token',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ForgotPasswordResetRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'Password reset successful' },
            '400': { description: 'Invalid token or payload' },
            '503': { description: 'Password reset service unavailable (migration missing)' },
          },
        },
      },
      '/auth/refresh': {
        post: {
          tags: ['Auth'],
          summary: 'Refresh access token',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RefreshTokenRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthTokensResponse' },
                },
              },
            },
            '401': { description: 'Invalid refresh token' },
          },
        },
      },
      '/auth/logout': {
        post: {
          tags: ['Auth'],
          summary: 'Revoke refresh token',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RefreshTokenRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/MessageResponse' },
                },
              },
            },
          },
        },
      },
      '/auth/logout-all': {
        post: {
          tags: ['Auth'],
          summary: 'Revoke all refresh tokens for current user',
          security: [{ bearerAuth: [] }],
          responses: {
            '200': { description: 'All sessions logged out' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/auth/delete-account/request-otp': {
        post: {
          tags: ['Auth'],
          summary: 'Send account-deletion OTP to current user email',
          security: [{ bearerAuth: [] }],
          responses: {
            '200': { description: 'OTP sent' },
            '400': { description: 'Account not active or missing email' },
            '401': { description: 'Unauthorized' },
            '404': { description: 'User not found' },
            '503': { description: 'Account deletion service unavailable (migration missing)' },
          },
        },
      },
      '/auth/delete-account': {
        delete: {
          tags: ['Auth'],
          summary: 'Delete current user account permanently using OTP verification',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/DeleteAccountRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'Account deleted successfully' },
            '400': { description: 'Invalid or expired OTP' },
            '401': { description: 'Unauthorized' },
            '404': { description: 'User not found' },
            '429': { description: 'Too many invalid OTP attempts' },
            '503': { description: 'Account deletion service unavailable (migration missing)' },
          },
        },
      },
      '/auth/referral-code/generate': {
        post: {
          tags: ['Auth'],
          summary: 'Generate a new referral code for current user',
          security: [{ bearerAuth: [] }],
          responses: {
            '201': { description: 'Referral code generated' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/auth/me': {
        get: {
          tags: ['Auth'],
          summary: 'Get current user profile',
          security: [{ bearerAuth: [] }],
          responses: {
            '200': { description: 'OK' },
            '401': { description: 'Unauthorized' },
          },
        },
        patch: {
          tags: ['Auth'],
          summary: 'Update current user profile (phone/password rotation)',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    phone: { type: 'string', nullable: true },
                    currentPassword: { type: 'string' },
                    newPassword: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Updated' },
            '400': { description: 'Validation error' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/foods': {
        get: {
          tags: ['Foods'],
          summary: 'List available foods',
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: {
                    type: 'array',
                    items: { $ref: '#/components/schemas/FoodItem' },
                  },
                },
              },
            },
          },
        },
        post: {
          tags: ['Foods'],
          summary: 'Create food item (Admin)',
          security: [{ adminBearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CreateFoodRequest' },
              },
            },
          },
          responses: {
            '201': {
              description: 'Created',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/FoodItem' },
                },
              },
            },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/foods/{id}': {
        get: {
          tags: ['Foods'],
          summary: 'Get a food item by id',
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/FoodItem' },
                },
              },
            },
            '404': { description: 'Not found' },
          },
        },
        put: {
          tags: ['Foods'],
          summary: 'Update food item (Admin)',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdateFoodRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/FoodItem' },
                },
              },
            },
            '401': { description: 'Unauthorized' },
            '404': { description: 'Not found' },
          },
        },
        delete: {
          tags: ['Foods'],
          summary: 'Soft delete food item (Admin)',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/MessageResponse' },
                },
              },
            },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/cart': {
        post: {
          tags: ['Cart'],
          summary: 'Add item to cart',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CartMutationRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'OK' },
            '401': { description: 'Unauthorized' },
          },
        },
        get: {
          tags: ['Cart'],
          summary: 'View cart',
          security: [{ bearerAuth: [] }],
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/CartResponse' },
                },
              },
            },
            '401': { description: 'Unauthorized' },
          },
        },
        put: {
          tags: ['Cart'],
          summary: 'Update cart item quantity',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CartMutationRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'OK' },
            '401': { description: 'Unauthorized' },
          },
        },
        delete: {
          tags: ['Cart'],
          summary: 'Clear cart',
          security: [{ bearerAuth: [] }],
          responses: {
            '200': { description: 'OK' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/orders': {
        get: {
          tags: ['Orders'],
          summary: "List current user's orders",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'status',
              in: 'query',
              required: false,
              schema: { type: 'string' },
            },
            {
              name: 'page',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 1 },
            },
            {
              name: 'limit',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 1, maximum: 100 },
            },
          ],
          responses: {
            '200': { description: 'OK' },
            '401': { description: 'Unauthorized' },
          },
        },
        post: {
          tags: ['Orders'],
          summary: 'Create order from cart',
          security: [{ bearerAuth: [] }],
          responses: {
            '201': {
              description: 'Created',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/CreateOrderResponse' },
                },
              },
            },
            '401': { description: 'Unauthorized' },
            '400': { description: 'Cart invalid or empty' },
          },
        },
      },
      '/orders/{id}': {
        get: {
          tags: ['Orders'],
          summary: 'Get order by id',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/OrderResponse' },
                },
              },
            },
            '401': { description: 'Unauthorized' },
            '404': { description: 'Not found' },
          },
        },
      },
      '/orders/{id}/coupon/validate': {
        post: {
          tags: ['Orders'],
          summary: 'Validate coupon for pending order',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['couponCode'],
                  properties: {
                    couponCode: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Coupon validation result' },
            '400': { description: 'Validation error' },
            '404': { description: 'Order or coupon not found' },
          },
        },
      },
      '/orders/{id}/coupon/apply': {
        post: {
          tags: ['Orders'],
          summary: 'Apply coupon to pending order',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['couponCode'],
                  properties: {
                    couponCode: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Coupon applied' },
            '400': { description: 'Validation error' },
            '404': { description: 'Order or coupon not found' },
          },
        },
      },
      '/orders/{id}/coupon': {
        delete: {
          tags: ['Orders'],
          summary: 'Remove coupon from pending order',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': { description: 'Coupon removed' },
            '400': { description: 'Validation error' },
            '404': { description: 'Order not found' },
          },
        },
      },
      '/orders/{id}/status': {
        patch: {
          tags: ['Orders'],
          summary: 'Update order status (Admin)',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdateOrderStatusRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/UpdateOrderStatusResponse' },
                },
              },
            },
            '401': { description: 'Unauthorized' },
            '400': { description: 'Invalid transition' },
          },
        },
      },
      '/orders/{id}/cancel': {
        post: {
          tags: ['Orders'],
          summary: 'Cancel pending order',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/MessageResponse' },
                },
              },
            },
            '401': { description: 'Unauthorized' },
            '400': { description: 'Cannot cancel' },
          },
        },
      },
      '/payments/initialize': {
        post: {
          tags: ['Payments'],
          summary: 'Initialize Paystack payment for an order',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['orderId'],
                  properties: {
                    orderId: { type: 'string', format: 'uuid' },
                    callbackUrl: { type: 'string', format: 'uri' },
                    saveCard: { type: 'boolean', description: 'Save reusable card token after successful payment' },
                  },
                },
              },
            },
          },
          responses: {
            '201': { description: 'Initialized' },
            '400': { description: 'Validation error' },
            '404': { description: 'Order not found' },
          },
        },
      },
      '/payments/cards': {
        post: {
          tags: ['Payments'],
          summary: 'Save a reusable card from a successful payment reference',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['reference'],
                  properties: {
                    reference: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '201': { description: 'Card saved' },
            '400': { description: 'Validation error' },
            '404': { description: 'Payment not found' },
          },
        },
        get: {
          tags: ['Payments'],
          summary: 'List saved cards for authenticated user',
          security: [{ bearerAuth: [] }],
          responses: {
            '200': {
              description: 'Saved cards',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      cards: {
                        type: 'array',
                        items: { $ref: '#/components/schemas/PaymentCard' },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/payments/cards/{cardId}': {
        patch: {
          tags: ['Payments'],
          summary: 'Set default saved card',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'cardId',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': { description: 'Default card updated' },
            '404': { description: 'Card not found' },
          },
        },
        delete: {
          tags: ['Payments'],
          summary: 'Delete a saved card',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'cardId',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': { description: 'Removed' },
            '404': { description: 'Card not found' },
          },
        },
      },
      '/payments/pay-with-saved-card': {
        post: {
          tags: ['Payments'],
          summary: 'Auto-debit a saved card for an order',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['orderId', 'cardId'],
                  properties: {
                    orderId: { type: 'string', format: 'uuid' },
                    cardId: { type: 'string', format: 'uuid' },
                  },
                },
              },
            },
          },
          responses: {
            '201': { description: 'Paid with saved card' },
            '400': { description: 'Validation error' },
            '402': { description: 'Automatic debit failed' },
            '404': { description: 'Order/card not found' },
          },
        },
      },
      '/payments/verify/{reference}': {
        get: {
          tags: ['Payments'],
          summary: 'Verify payment by reference and confirm order payment',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'reference',
              in: 'path',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': { description: 'Verified' },
            '404': { description: 'Payment not found' },
          },
        },
      },
      '/payments/webhook/paystack': {
        post: {
          tags: ['Payments'],
          summary: 'Paystack webhook endpoint (signature verified)',
          responses: {
            '200': { description: 'Processed' },
            '401': { description: 'Invalid signature' },
          },
        },
      },
      '/admin/auth/bootstrap': {
        post: {
          tags: ['Admin'],
          summary: 'Bootstrap first admin account',
          security: [{ AdminBootstrapKey: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminBootstrapRequest' },
              },
            },
          },
          responses: {
            '201': { description: 'Admin created' },
            '401': { description: 'Unauthorized bootstrap request' },
          },
        },
      },
      '/admin/auth/login': {
        post: {
          tags: ['Admin'],
          summary: 'Admin login (requires OTP on new device/IP)',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminLoginRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'Login successful' },
            '202': { description: 'OTP required for this device/IP' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/admin/auth/refresh': {
        post: {
          tags: ['Admin'],
          summary: 'Refresh admin token',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RefreshTokenRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'Token refreshed' },
            '401': { description: 'Invalid refresh token' },
          },
        },
      },
      '/admin/auth/logout': {
        post: {
          tags: ['Admin'],
          summary: 'Logout admin',
          security: [{ adminBearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RefreshTokenRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'Logged out' },
          },
        },
      },
      '/admin/auth/logout-all': {
        post: {
          tags: ['Admin'],
          summary: 'Logout admin from all sessions',
          security: [{ adminBearerAuth: [] }],
          responses: {
            '200': { description: 'All admin sessions logged out' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/admin/me': {
        get: {
          tags: ['Admin'],
          summary: 'Current admin profile',
          security: [{ adminBearerAuth: [] }],
          responses: {
            '200': { description: 'OK' },
            '401': { description: 'Invalid admin token' },
          },
        },
      },
      '/admin/dashboard': {
        get: {
          tags: ['Admin'],
          summary: 'Admin dashboard metrics',
          security: [{ adminBearerAuth: [] }],
          responses: {
            '200': { description: 'OK' },
          },
        },
      },
      '/admin/admins': {
        post: {
          tags: ['Admin'],
          summary: 'Create admin account (super admin)',
          security: [{ adminBearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminBootstrapRequest' },
              },
            },
          },
          responses: {
            '201': { description: 'Created' },
            '403': { description: 'Super admin required' },
          },
        },
      },
      '/admin/users': {
        get: {
          tags: ['Admin'],
          summary: 'List users',
          security: [{ adminBearerAuth: [] }],
          responses: {
            '200': { description: 'OK' },
          },
        },
      },
      '/admin/users/{id}': {
        get: {
          tags: ['Admin'],
          summary: 'Get user details',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': { description: 'OK' },
            '404': { description: 'User not found' },
          },
        },
      },
      '/admin/users/{id}/status': {
        patch: {
          tags: ['Admin'],
          summary: 'Update user verification/suspension',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminUserStatusUpdateRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'Updated' },
          },
        },
      },
      '/admin/orders': {
        get: {
          tags: ['Admin'],
          summary: 'List orders',
          security: [{ adminBearerAuth: [] }],
          responses: {
            '200': { description: 'OK' },
          },
        },
      },
      '/admin/orders/{id}': {
        get: {
          tags: ['Admin'],
          summary: 'Get order details',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': { description: 'OK' },
          },
        },
      },
      '/admin/orders/{id}/status': {
        patch: {
          tags: ['Admin'],
          summary: 'Update order status',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdateOrderStatusRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'Updated' },
          },
        },
      },
      '/admin/coupons': {
        post: {
          tags: ['Admin'],
          summary: 'Create coupon',
          security: [{ adminBearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['discountType', 'discountValue'],
                  properties: {
                    code: { type: 'string' },
                    description: { type: 'string' },
                    discountType: { type: 'string', enum: ['percentage', 'fixed'] },
                    discountValue: { type: 'number' },
                    maxRedemptions: { type: 'integer', nullable: true },
                    startsAt: { type: 'string', format: 'date-time', nullable: true },
                    expiresAt: { type: 'string', format: 'date-time', nullable: true },
                    isActive: { type: 'boolean' },
                  },
                },
              },
            },
          },
          responses: {
            '201': { description: 'Created' },
            '400': { description: 'Validation error' },
          },
        },
        get: {
          tags: ['Admin'],
          summary: 'List coupons',
          security: [{ adminBearerAuth: [] }],
          responses: {
            '200': { description: 'OK' },
          },
        },
      },
      '/admin/referral-codes': {
        post: {
          tags: ['Admin'],
          summary: 'Create user referral code',
          security: [{ adminBearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['userId'],
                  properties: {
                    userId: { type: 'string', format: 'uuid' },
                    referralCode: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '201': { description: 'Created' },
            '404': { description: 'User not found' },
          },
        },
        get: {
          tags: ['Admin'],
          summary: 'List user referral codes',
          security: [{ adminBearerAuth: [] }],
          responses: {
            '200': { description: 'OK' },
          },
        },
      },
      '/admin/disputes': {
        post: {
          tags: ['Admin'],
          summary: 'Create dispute',
          security: [{ adminBearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminCreateDisputeRequest' },
              },
            },
          },
          responses: {
            '201': { description: 'Created' },
          },
        },
        get: {
          tags: ['Admin'],
          summary: 'List disputes',
          security: [{ adminBearerAuth: [] }],
          responses: {
            '200': { description: 'OK' },
          },
        },
      },
      '/admin/disputes/{id}': {
        get: {
          tags: ['Admin'],
          summary: 'Get dispute details',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          responses: {
            '200': { description: 'OK' },
            '404': { description: 'Dispute not found' },
          },
        },
        patch: {
          tags: ['Admin'],
          summary: 'Update dispute',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminUpdateDisputeRequest' },
              },
            },
          },
          responses: {
            '200': { description: 'Updated' },
          },
        },
      },
      '/admin/disputes/{id}/comments': {
        post: {
          tags: ['Admin'],
          summary: 'Add dispute comment',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminDisputeCommentRequest' },
              },
            },
          },
          responses: {
            '201': { description: 'Created' },
          },
        },
      },
      '/admin/disputes/{id}/resolve': {
        post: {
          tags: ['Admin'],
          summary: 'Resolve dispute explicitly',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', format: 'uuid' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['resolutionNotes'],
                  properties: {
                    resolutionNotes: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Resolved' },
            '400': { description: 'Invalid status or payload' },
            '404': { description: 'Dispute not found' },
          },
        },
      },
      '/admin/audit-logs': {
        get: {
          tags: ['Admin'],
          summary: 'List admin audit logs',
          security: [{ adminBearerAuth: [] }],
          parameters: [
            { name: 'action', in: 'query', required: false, schema: { type: 'string' } },
            { name: 'method', in: 'query', required: false, schema: { type: 'string' } },
            { name: 'statusCode', in: 'query', required: false, schema: { type: 'integer' } },
            { name: 'requestId', in: 'query', required: false, schema: { type: 'string' } },
            { name: 'from', in: 'query', required: false, schema: { type: 'string', format: 'date-time' } },
            { name: 'to', in: 'query', required: false, schema: { type: 'string', format: 'date-time' } },
            { name: 'page', in: 'query', required: false, schema: { type: 'integer', minimum: 1 } },
            { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1, maximum: 100 } },
          ],
          responses: {
            '200': { description: 'OK' },
          },
        },
      },
      '/health': {
        get: {
          tags: ['System'],
          summary: 'Health check',
          responses: {
            '200': {
              description: 'OK',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/HealthResponse' },
                },
              },
            },
          },
        },
      },
      '/ready': {
        get: {
          tags: ['System'],
          summary: 'Readiness check (DB)',
          responses: {
            '200': {
              description: 'READY',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/HealthResponse' },
                },
              },
            },
            '503': {
              description: 'NOT_READY',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: { status: { type: 'string' } },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
  apis: [],
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = {
  swaggerSpec,
};
