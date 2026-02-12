const swaggerJSDoc = require('swagger-jsdoc');

const serverUrl = process.env.SWAGGER_SERVER_URL;

const options = {
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'Glossy_Gly-Kitchen API',
      version: '1.2.0',
      description: 'Production-ready food ordering backend API with auth, admin, foods, cart, orders, and disputes.',
    },
    servers: [
      {
        url: serverUrl,
      },
    ],
    tags: [
      { name: 'Auth' },
      { name: 'Admin' },
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
        AdminApiKey: {
          type: 'apiKey',
          in: 'header',
          name: 'x-admin-key',
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
        ResendOtpRequest: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
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
          security: [{ AdminApiKey: [] }],
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
        put: {
          tags: ['Foods'],
          summary: 'Update food item (Admin)',
          security: [{ AdminApiKey: [] }],
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
          security: [{ AdminApiKey: [] }],
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
      '/orders/{id}/status': {
        patch: {
          tags: ['Orders'],
          summary: 'Update order status (Admin)',
          security: [{ AdminApiKey: [] }],
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
