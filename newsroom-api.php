<?php

/**
 * Plugin Name: Newsroom API
 * Description: Provides custom REST API endpoints for mobile apps.
 * Version: 1.0
 * Author: Code and Core
 */

if (!defined('ABSPATH')) exit;
if (!defined('JWT_SECRET_KEY')) {
    define('JWT_SECRET_KEY', 'f9J!2k#93@LqX0mZ8a$KpR7E*YwTn4H6C%Q@1V');
}

/**
 * -------------------------------------------------
 * Register Region Taxonomy
 * -------------------------------------------------
 */
function newsroom_register_region_taxonomy()
{

    register_taxonomy(
        'region',
        ['post'], // or custom post type like ['news']
        [
            'label'             => 'Region',
            'hierarchical'      => true,
            'public'            => false, // NOT public on frontend
            'show_ui'           => true,  // still visible in WP admin
            'show_admin_column' => true,
            'show_in_rest'      => true,  // for Gutenberg / REST API
            'rewrite'           => false, // no frontend URLs
        ]
    );
}
add_action('init', 'newsroom_register_region_taxonomy');


/**
 * -------------------------------------------------
 * Plugin Activation Hook
 * (Runs ONCE when plugin is activated)
 * -------------------------------------------------
 */
function newsroom_api_activate()
{

    // Register taxonomy before flushing rules
    newsroom_register_region_taxonomy();

    // Flush rewrite rules ONCE
    flush_rewrite_rules();
}
register_activation_hook(__FILE__, 'newsroom_api_activate');


/**
 * -------------------------------------------------
 * Plugin Deactivation Hook
 * -------------------------------------------------
 */
function newsroom_api_deactivate()
{
    flush_rewrite_rules();
}
register_deactivation_hook(__FILE__, 'newsroom_api_deactivate');


//Category Image Upload
add_action('category_edit_form_fields', 'blog_category_image_field_edit');

function blog_category_image_field_edit($term)
{

    $image_id  = get_term_meta($term->term_id, 'category_image', true);
    $image_url = $image_id ? wp_get_attachment_url($image_id) : '';
?>
    <tr class="form-field">
        <th scope="row">
            <label>Category Image</label>
        </th>
        <td>
            <input type="hidden" name="category_image" id="category_image"
                value="<?php echo esc_attr($image_id); ?>">

            <div id="category  -image-preview">
                <?php if ($image_url): ?>
                    <img src="<?php echo esc_url($image_url); ?>" style="max-width:150px;">
                <?php endif; ?>
            </div>

            <button type="button" class="button upload-category-image">
                Upload / Select Image
            </button>

            <button type="button" class="button remove-category-image"
                <?php if (!$image_id) echo 'style="display:none;"'; ?>>
                Remove
            </button>
        </td>
    </tr>
<?php
}

add_action('edited_category', 'save_blog_category_image');

function save_blog_category_image($term_id)
{
    if (isset($_POST['category_image'])) {
        update_term_meta($term_id, 'category_image', intval($_POST['category_image']));
    }
}

add_action('admin_enqueue_scripts', 'blog_category_image_media');
function blog_category_image_media($hook)
{

    if ($hook !== 'term.php' && $hook !== 'edit-tags.php') {
        return;
    }

    wp_enqueue_media();

    wp_enqueue_script(
        'category-image-js',
        plugin_dir_url(__FILE__) . '/assets/js/category-image.js',
        ['jquery'],
        null,
        true
    );
}


/**
 * REGISTER ROUTES
 */
add_action('rest_api_init', 'newsroomapi_routes');
function newsroomapi_routes()
{
    // LOGIN API
    register_rest_route('loginapi/v1', '/login', [
        'methods'  => 'POST',
        'callback' => 'newsroomapi_login',
        'permission_callback' => '__return_true',
    ]);

    //Social Login
    register_rest_route('myapi/v1', '/social-login', [
        'methods'  => 'POST',
        'callback' => 'newsroomapi_social_login',
        'permission_callback' => '__return_true',
    ]);


    // REGISTER API
    register_rest_route('registerapi/v1', '/register', [
        'methods'  => 'POST',
        'callback' => 'newsroomapi_register',
        'permission_callback' => '__return_true',
    ]);

    //profile update
    register_rest_route('myapi/v1', '/update-profile', [
        'methods'  => 'POST',
        'callback' => 'my_api_update_profile',
        'permission_callback' => '__return_true',
    ]);


    //get categories list
    register_rest_route('myapi/v1', '/categories', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_categories',
        'permission_callback' => '__return_true' // public API
    ]);


    //get categories list
    register_rest_route('myapi/v1', '/regions', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_regions',
        'permission_callback' => '__return_true' // public API
    ]);

    //get Posts by Categories
    register_rest_route('myapi/v1', '/posts', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_posts_by_category',
        'permission_callback' => '__return_true'
    ]);

    //Single Post
    register_rest_route('myapi/v1', '/single-post', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_single_post',
        'permission_callback' => '__return_true'
    ]);


    // Forgot Password endpoint
    register_rest_route('myapi/v1', '/forgot-password', [
        'methods' => 'POST',
        'callback' => 'myapi_forgot_password',
        'permission_callback' => '__return_true',
    ]);


    //otp verify
    register_rest_route('myapi/v1', '/verify-otp', [
        'methods'  => 'POST',
        'callback' => 'myapi_verify_otp',
        'permission_callback' => '__return_true',
    ]);

    //Reset Password
    register_rest_route('myapi/v1', '/reset-password', [
        'methods'  => 'POST',
        'callback' => 'myapi_reset_password',
        'permission_callback' => '__return_true',
    ]);

    // Top Trending Posts
    register_rest_route('myapi/v1', '/trending-posts', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_trending_posts',
        'permission_callback' => '__return_true',
    ]);


    register_rest_route('myapi/v1', '/logout', [
        'methods'  => 'POST',
        'callback' => 'newsroomapi_logout',
        'permission_callback' => '__return_true',
    ]);

    // Search API
    register_rest_route('myapi/v1', '/search', [
        'methods' => 'GET',
        'callback' => 'myapi_search_posts',
        'permission_callback' => '__return_true',
    ]);

    //User Profile Get
    register_rest_route('myapi/v1', '/profile', [
        'methods' => 'GET',
        'callback' => 'myapi_get_user_profile',
        'permission_callback' => '__return_true',
    ]);

    //Video
    register_rest_route('myapi/v1', '/latest-videos', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_latest_videos',
        'permission_callback' => '__return_true',
    ]);

    //Save Posts
    register_rest_route('myapi/v1', '/save-post', [
        'methods'  => 'GET',
        'callback' => 'myapi_save_posts',
        'permission_callback' => '__return_true',
    ]);

    // Remove saved posts
    register_rest_route('myapi/v1', '/remove-saved-post', [
        'methods'  => 'DELETE',
        'callback' => 'myapi_remove_saved_posts',
        'permission_callback' => '__return_true',
    ]);

    // List of all  saved posts
    register_rest_route('myapi/v1', '/show-saved-post', [
        'methods'  => 'GET',
        'callback' => 'myapi_show_all_saved_posts',
        'permission_callback' => '__return_true',
    ]);

    // Choose Cat/Region
    register_rest_route('myapi/v1', '/save-selection', [
        'methods'  => 'POST',
        'callback' => 'myapi_save_user_selection',
        'permission_callback' => '__return_true',
    ]);

    // Recommended for You - Posts from user's selected categories
    register_rest_route('myapi/v1', '/recommended-posts', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_recommended_posts',
        'permission_callback' => '__return_true',
    ]);



    // Notification API  
    register_rest_route('myapi/v1', '/notification', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_notification',
        'permission_callback' => '__return_true',
    ]);


    // Register route continue-reading
    register_rest_route('myapi/v1', '/continue-reading', [
        'methods'  => 'POST',
        'callback' => 'myapi_continue_reading_post',
        'permission_callback' => '__return_true',
    ]);

    // Continue Reading – Get pending posts
    register_rest_route('myapi/v1', '/get-continue-reading', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_continue_reading',
        'permission_callback' => '__return_true',
    ]);

    // Continue Reading – Delete single post
    register_rest_route('myapi/v1', '/continue-reading', [
        'methods'  => 'DELETE',
        'callback' => 'myapi_delete_continue_reading',
        'permission_callback' => '__return_true',
    ]);


    // Feedback API
    register_rest_route('myapi/v1', '/feedback', [
        'methods'  => 'POST',
        'callback' => 'myapi_save_feedback_authenticated',
        'permission_callback' => '__return_true',
    ]);

    register_rest_route('myapi/v1', '/user-settings', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_user_settings',
        'permission_callback' => '__return_true',
    ]);

    register_rest_route('myapi/v1', '/user-settings', [
        'methods'  => 'POST',
        'callback' => 'myapi_save_user_settings',
        'permission_callback' => '__return_true',
    ]);

    /**
     * Register Verify JWT API
     */
    register_rest_route('myapi/v1', '/verify-token', [
        'methods'  => 'POST',
        'callback' => 'myapi_verify_token',
        'permission_callback' => '__return_true',
    ]);

    // register_rest_route('api/v1', '/push', [
    //     'methods'  => 'POST',
    //     'callback' => 'handlePushNotificationRequest',
    //     'permission_callback' => '__return_true',
    // ]);


    // Register Device Token
    register_rest_route('myapi/v1', '/register-token', [
        'methods'  => 'POST',
        'callback' => 'myapi_register_device_token',
        'permission_callback' => '__return_true',
    ]);

    register_rest_route('myapi/v1', '/delete-account', [
        'methods' => 'DELETE',
        'callback' => 'myapi_delete_account',
        'permission_callback' => '__return_true', // JWT verification is inside the callback
    ]);


    // Dropdown API
    register_rest_route('myapi/v1', '/ad-placements', [
        'methods' => 'GET',
        'callback' => 'newsroom_get_ad_placements',
        'permission_callback' => '__return_true'
    ]);

    //Ad Map API
    register_rest_route('myapi/v1', '/advertise', array(
        'methods'  => 'POST',
        'callback' => 'newsroom_advertise_api',
        'permission_callback' => '__return_true'
    ));


    // Home API
    register_rest_route('myapi/v1', '/home', [
        'methods'  => 'GET',
        'callback' => 'myapi_get_home_data',
        'permission_callback' => '__return_true',
    ]);

    register_rest_route('myapi/v1', '/post-detail', array(
        'methods'  => 'GET',
        'callback' => 'myapi_get_single_post_detail',
        'permission_callback' => '__return_true',
    ));
}


function myapi_verify_token(WP_REST_Request $request)
{

    // Read Authorization header safely
    $auth_header = $request->get_header('authorization');

    if (!$auth_header) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Authorization header missing'
        ], 401);
    }

    // Call your JWT helper
    $payload = newsroomapi_verify_jwt($auth_header);

    if (!$payload) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Invalid or expired token'
        ], 401);
    }

    return new WP_REST_Response([
        'status'  => true,
        'payload' => $payload
    ], 200);
}



/**
 * Verify JWT Token
 */
function newsroomapi_verify_jwt($auth_header)
{

    if (empty($auth_header) || stripos($auth_header, 'Bearer ') !== 0) {
        return false;
    }

    // Keep raw JWT intact, but trim surrounding whitespace
    $jwt = trim(str_ireplace('Bearer ', '', $auth_header));

    // Validate token structure: three base64url parts
    if (!preg_match('/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/', $jwt)) {
        return false;
    }

    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        return false;
    }

    list($header_b64, $payload_b64, $signature_b64) = $parts;

    // Recompute expected signature (binary), then base64url-encode it for comparison
    $signature_raw = hash_hmac('sha256', $header_b64 . '.' . $payload_b64, JWT_SECRET_KEY, true);
    $expected_signature = jwt_base64url_encode($signature_raw);

    if (!hash_equals($expected_signature, $signature_b64)) {
        return false;
    }

    $decoded_payload_raw = jwt_base64url_decode($payload_b64);
    if ($decoded_payload_raw === false) {
        return false;
    }

    $payload = json_decode($decoded_payload_raw, true);
    if (!is_array($payload) || empty($payload['sub']) || empty($payload['exp']) || $payload['exp'] < time()) {
        return false;
    }

    return $payload;
}

/**
 * Base64URL Encoding Helper
 */
function jwt_base64url_encode($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function jwt_base64url_decode($data)
{
    // Add padding back
    $mod = strlen($data) % 4;
    if ($mod) {
        $data .= str_repeat('=', 4 - $mod);
    }

    $trans = strtr($data, '-_', '+/');
    $decoded = base64_decode($trans, true);

    if ($decoded === false) {
        return false;
    }

    return $decoded;
}


/**
 * LOGIN API (JWT for Mobile App)
 */
function newsroomapi_login($request)
{

    $username = sanitize_text_field($request->get_param('username'));
    $password = $request->get_param('password');

    if (!$username || !$password) {
        return new WP_REST_Response([
            'status' => 'error',
            'message' => 'Username and password required'
        ], 400);
    }

    $user = wp_authenticate($username, $password);

    if (is_wp_error($user)) {
        return new WP_REST_Response([
            'status' => 'error',
            'message' => 'Invalid username or password'
        ], 401);
    }

    /* ---------- JWT GENERATION ---------- */
    // Use base64url encoding for header/payload/signature so verification matches
    $header_b64 = jwt_base64url_encode(json_encode([
        'alg' => 'HS256',
        'typ' => 'JWT'
    ]));

    $payload = [
        'iss' => get_site_url(),
        'sub' => $user->ID,
        'iat' => time(),
        'exp' => time() + (30 * 24 * 60 * 60),
        'jti' => wp_generate_uuid4()
    ];

    $payload_b64 = jwt_base64url_encode(json_encode($payload));

    $signature_raw = hash_hmac(
        'sha256',
        $header_b64 . '.' . $payload_b64,
        JWT_SECRET_KEY,
        true
    );

    $signature_b64 = jwt_base64url_encode($signature_raw);

    $jwt = $header_b64 . '.' . $payload_b64 . '.' . $signature_b64;


    /* ---------- STORE TOKEN IN DB ---------- */
    update_user_meta($user->ID, '_jwt_token', $jwt);
    update_user_meta($user->ID, '_jwt_jti', $payload['jti']);
    update_user_meta($user->ID, '_jwt_exp', $payload['exp']);

    return new WP_REST_Response([
        'status' => true,
        'token'  => sanitize_text_field($jwt),
        'user'   => [
            'id'       => (int) $user->ID,
            'username' => sanitize_text_field($user->user_login),
            'email'    => sanitize_email($user->user_email)
        ]
    ], 200);
}



/**
 * Social Login
 */
function newsroomapi_social_login(WP_REST_Request $request)
{

    $provider = sanitize_text_field($request->get_param('provider'));
    $token    = $request->get_param('token');

    if (!$provider || !$token) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Provider and token required'
        ], 400);
    }

    switch ($provider) {
        case 'google':
            $userData = newsroomapi_verify_google($token);
            break;

        case 'facebook':
            $userData = newsroomapi_verify_facebook($token);
            break;

        case 'apple':
            $userData = newsroomapi_verify_apple($token);
            break;

        default:
            return new WP_REST_Response([
                'status' => false,
                'message' => 'Invalid provider'
            ], 400);
    }

    if (!$userData || empty($userData['email'])) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Invalid social token'
        ], 401);
    }

    return newsroomapi_social_login_or_register($userData, $provider);
}

//GOOGLE login
function newsroomapi_verify_google($token)
{

    $response = wp_remote_get(
        'https://oauth2.googleapis.com/tokeninfo?id_token=' . $token
    );

    if (is_wp_error($response)) return false;

    $data = json_decode(wp_remote_retrieve_body($response), true);

    if (empty($data['email'])) return false;

    return [
        'email'     => sanitize_email($data['email']),
        'name'      => sanitize_text_field($data['name'] ?? ''),
        'social_id' => sanitize_text_field($data['sub']),
    ];
}

//FacebooK Login
function newsroomapi_verify_facebook($token)
{

    $response = wp_remote_get(
        'https://graph.facebook.com/me?fields=id,name,email&access_token=' . $token
    );

    if (is_wp_error($response)) return false;

    $data = json_decode(wp_remote_retrieve_body($response), true);

    if (empty($data['email'])) return false;

    return [
        'email'     => sanitize_email($data['email']),
        'name'      => sanitize_text_field($data['name'] ?? ''),
        'social_id' => sanitize_text_field($data['id']),
    ];
}

//Apple Login
function newsroomapi_verify_apple($token)
{

    $parts = explode('.', $token);
    if (count($parts) < 2) return false;

    $payload = json_decode(base64_decode($parts[1]), true);
    if (empty($payload['sub'])) return false;

    return [
        'email'     => sanitize_email($payload['email'] ?? ''),
        'name'      => '',
        'social_id' => sanitize_text_field($payload['sub']),
    ];
}

// Register/Login Social
function newsroomapi_social_login_or_register($userData, $provider)
{
    $email = sanitize_email($userData['email']);
    $name  = sanitize_text_field($userData['name'] ?? '');

    // ---- Handle first & last name ----
    $name_parts = newsroomapi_split_name($name);
    $first_name = $name_parts['first_name'];
    $last_name  = $name_parts['last_name'];

    $user = get_user_by('email', $email);
    $is_new_user = false;

    if (!$user) {

        // ---- Generate username ----
        $username = newsroomapi_generate_username($email, $name);

        $user_id = wp_insert_user([
            'user_login'   => $username,
            'user_pass'    => wp_generate_password(20),
            'user_email'   => $email,
            'first_name'   => $first_name,
            'last_name'    => $last_name,
            'display_name' => trim($first_name . ' ' . $last_name),
            'role'         => get_option('default_role')
        ]);

        if (is_wp_error($user_id)) {
            return new WP_REST_Response([
                'status' => false,
                'message' => $user_id->get_error_message()
            ], 500);
        }

        update_user_meta($user_id, 'social_provider', $provider);
        update_user_meta($user_id, 'social_id', sanitize_text_field($userData['social_id']));

        $is_new_user = true;

    } else {

        $user_id = $user->ID;

        // Soft delete protection
        if (get_user_meta($user_id, 'is_deleted', true) == 1) {
            return new WP_REST_Response([
                'status' => false,
                'message' => 'Your account has been deleted. Please contact support.'
            ], 403);
        }
    }

    // ---------- JWT (unchanged) ----------
    $header_b64 = jwt_base64url_encode(json_encode([
        'alg' => 'HS256',
        'typ' => 'JWT'
    ]));

    $payload = [
        'iss' => get_site_url(),
        'sub' => $user_id,
        'iat' => time(),
        'exp' => time() + (7 * 24 * 60 * 60),
        'jti' => wp_generate_uuid4()
    ];

    $payload_b64 = jwt_base64url_encode(json_encode($payload));

    $signature_raw = hash_hmac(
        'sha256',
        $header_b64 . '.' . $payload_b64,
        JWT_SECRET_KEY,
        true
    );

    $signature_b64 = jwt_base64url_encode($signature_raw);
    $jwt = $header_b64 . '.' . $payload_b64 . '.' . $signature_b64;

    update_user_meta($user_id, '_jwt_token', $jwt);
    update_user_meta($user_id, '_jwt_jti', $payload['jti']);
    update_user_meta($user_id, '_jwt_exp', $payload['exp']);

    $user_obj = get_user_by('id', $user_id);

    // ✅ Final correct response
    return new WP_REST_Response([
        'status' => true,
        'token'  => $jwt,
        'user'   => [
            'id'         => (int) $user_id,
            'username'   => $user_obj->user_login,
            'first_name' => $user_obj->first_name,
            'last_name'  => $user_obj->last_name,
            'email'      => $user_obj->user_email
        ],
        'is_new_user' => $is_new_user
    ], 200);
}

function newsroomapi_generate_username($email, $full_name = '')
{
    if ($email) {
        $base = sanitize_user(current(explode('@', $email)));
    } else {
        $base = sanitize_user(str_replace(' ', '', strtolower($full_name)));
    }

    if (!$base) $base = 'user';

    $username = $base;
    $i = 1;

    while (username_exists($username)) {
        $username = $base . $i;
        $i++;
    }

    return $username;
}

function newsroomapi_split_name($name)
{
    $name = trim($name);
    if (!$name) return ['first_name' => '', 'last_name' => ''];

    $parts = preg_split('/\s+/', $name, 2);

    return [
        'first_name' => sanitize_text_field($parts[0] ?? ''),
        'last_name'  => sanitize_text_field($parts[1] ?? '')
    ];
}



/**
 * REGISTER API (with JWT token + default WP fields)
 */
function newsroomapi_register($request)
{
    $first_name = sanitize_text_field($request->get_param('first_name'));
    $last_name  = sanitize_text_field($request->get_param('last_name'));
    $username   = sanitize_text_field($request->get_param('username'));
    $email      = sanitize_email($request->get_param('email'));
    $password   = $request->get_param('password');

    // -------------------------
    // Validate inputs
    // -------------------------
    if (!$first_name || !$last_name || !$username || !$email || !$password) {
        return new WP_REST_Response([
            'status'  => 'error',
            'message' => 'All fields required'
        ], 400);
    }

    if (!is_email($email)) {
        return new WP_REST_Response([
            'status'  => 'error',
            'message' => 'Invalid email format'
        ], 400);
    }

    if (strlen($password) < 6) {
        return new WP_REST_Response([
            'status'  => 'error',
            'message' => 'Password must be at least 6 characters'
        ], 400);
    }

    if (username_exists($username) || email_exists($email)) {
        return new WP_REST_Response([
            'status'  => 'error',
            'message' => 'User already exists'
        ], 409);
    }

    // -------------------------
    // Create user (default WP way)
    // -------------------------
    $user_id = wp_insert_user([
        'user_login' => $username,
        'user_pass'  => $password,
        'user_email' => $email,
        'first_name' => $first_name,
        'last_name'  => $last_name,
        'role'       => get_option('default_role') // same as WordPress
    ]);

    if (is_wp_error($user_id)) {
        return new WP_REST_Response([
            'status'  => 'error',
            'message' => $user_id->get_error_message()
        ], 500);
    }

    // -------------------------
    // JWT GENERATION
    // -------------------------
    $header_b64 = jwt_base64url_encode(json_encode([
        'alg' => 'HS256',
        'typ' => 'JWT'
    ]));

    $payload = [
        'iss' => get_site_url(),
        'sub' => $user_id,
        'iat' => time(),
        'exp' => time() + (30 * 24 * 60 * 60),
        'jti' => wp_generate_uuid4()
    ];

    $payload_b64 = jwt_base64url_encode(json_encode($payload));

    $signature_raw = hash_hmac(
        'sha256',
        $header_b64 . '.' . $payload_b64,
        JWT_SECRET_KEY,
        true
    );

    $signature_b64 = jwt_base64url_encode($signature_raw);

    $jwt = $header_b64 . '.' . $payload_b64 . '.' . $signature_b64;

    // -------------------------
    // Store token
    // -------------------------
    update_user_meta($user_id, '_jwt_token', $jwt);
    update_user_meta($user_id, '_jwt_jti', $payload['jti']);
    update_user_meta($user_id, '_jwt_exp', $payload['exp']);

    // -------------------------
    // Response
    // -------------------------
    return new WP_REST_Response([
        'status' => true,
        'token'  => sanitize_text_field($jwt),
        'user'   => [
            'id'         => (int) $user_id,
            'first_name' => $first_name,
            'last_name'  => $last_name,
            'username'   => $username,
            'email'      => $email
        ],
        'message' => 'Registration successful'
    ], 201);
}




/**
 * Update Profile Endpoint
 */
/**
 * Update Profile Endpoint (supports multipart/form-data)
 * Interests field depends on user's selected category preferences
 */
function my_api_update_profile(WP_REST_Request $request)
{
    // 🔐 Verify JWT
    $payload = newsroomapi_verify_jwt(
        $request->get_header('authorization')
    );

    if (!is_array($payload) || empty($payload['sub'])) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Invalid or expired token'
        ], 401);
    }

    $user_id = absint($payload['sub']);

    // -----------------------------
    // Sanitize inputs
    // -----------------------------
    $first_name = sanitize_text_field($request->get_param('first_name'));
    $last_name  = sanitize_text_field($request->get_param('last_name'));
    $email      = sanitize_email($request->get_param('email'));
    $phone      = sanitize_text_field($request->get_param('phone_number'));
    $interests  = $request->get_param('interests');

    // ❌ username intentionally NOT taken from request (locked)

    // -----------------------------
    // Fetch allowed categories
    // -----------------------------
    $selected_categories = get_user_meta($user_id, 'selected_category', true);

    if (is_string($selected_categories)) {
        $selected_categories = explode(',', $selected_categories);
    }

    if (!is_array($selected_categories)) {
        $selected_categories = [];
    }

    $selected_categories = array_map('absint', $selected_categories);
    $selected_categories = array_filter($selected_categories);

    // -----------------------------
    // Validate interests
    // -----------------------------
    $final_interests = [];

    if (!empty($interests)) {

        if (is_string($interests)) {
            $decoded = json_decode($interests, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                $interests = $decoded;
            }
        }

        if (!is_array($interests)) {
            $interests = [$interests];
        }

        $interests = array_map('absint', $interests);
        $interests = array_filter($interests);

        $invalid = array_diff($interests, $selected_categories);

        if (!empty($invalid)) {
            return new WP_REST_Response([
                'status'  => false,
                'message' => 'One or more interests are not in selected categories',
                'invalid_ids' => array_values($invalid)
            ], 400);
        }

        $final_interests = array_values(array_unique($interests));
    }

    // -----------------------------
    // Update wp_users table
    // -----------------------------
    $userdata = ['ID' => $user_id];

    if (!empty($first_name)) {
        $userdata['first_name'] = $first_name;
    }

    if (!empty($last_name)) {
        $userdata['last_name'] = $last_name;
    }

    if (!empty($email) && is_email($email)) {

        if (email_exists($email) && email_exists($email) != $user_id) {
            return new WP_REST_Response([
                'status'  => false,
                'message' => 'Email already in use'
            ], 409);
        }

        $userdata['user_email'] = $email;
    }

    if (count($userdata) > 1) {
        wp_update_user($userdata);
    }

    // Auto update display name like WP
    if ($first_name || $last_name) {
        wp_update_user([
            'ID' => $user_id,
            'display_name' => trim($first_name . ' ' . $last_name)
        ]);
    }

    // -----------------------------
    // Update user meta
    // -----------------------------
    if (!empty($phone)) {
        update_user_meta($user_id, 'phone', $phone);
    }

    update_user_meta($user_id, 'interests', $final_interests);

    // -----------------------------
    // Handle profile image upload
    // -----------------------------
    if (!empty($_FILES['profile_image'])) {

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/media.php';
        require_once ABSPATH . 'wp-admin/includes/image.php';

        $file = $_FILES['profile_image'];

        $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        $mime_type = mime_content_type($file['tmp_name']);

        if (!in_array($mime_type, $allowed_types, true)) {
            return new WP_REST_Response([
                'status'  => false,
                'message' => 'Only JPEG, PNG, GIF, and WebP images are allowed'
            ], 400);
        }

        if ($file['size'] > 5 * 1024 * 1024) {
            return new WP_REST_Response([
                'status'  => false,
                'message' => 'File size must not exceed 5MB'
            ], 400);
        }

        $upload = wp_handle_upload($file, ['test_form' => false]);

        if (!empty($upload['error'])) {
            return new WP_REST_Response([
                'status'  => false,
                'message' => $upload['error']
            ], 400);
        }

        update_user_meta($user_id, 'profile_image', esc_url_raw($upload['url']));
    }

    return new WP_REST_Response([
        'status'  => true,
        'message' => 'Profile updated successfully'
    ], 200);
}




/**
 * Callback: Get all categories with image + placeholder
 */
function myapi_get_categories(WP_REST_Request $request)
{

    $categories = get_categories([
        'hide_empty' => false
    ]);

    // 👉 Default placeholder image
    $placeholder = plugin_dir_url(__FILE__) . 'assets/images/category-placeholder.png';

    $result = [];

    foreach ($categories as $cat) {

        $image_id = get_term_meta($cat->term_id, 'category_image', true);
        $image_url = $image_id ? wp_get_attachment_url($image_id) : $placeholder;

        $videos = [];

        // ==============================
        // 🎥 ONLY FOR VIDEO CATEGORY
        // ==============================
        if ($cat->slug === 'video') {

            $video_query = new WP_Query([
                'post_type'      => 'post',
                'post_status'    => 'publish',
                'posts_per_page' => 3,
                'cat'            => $cat->term_id,
                'orderby'        => 'date',
                'order'          => 'DESC'
            ]);

            if ($video_query->have_posts()) {
                foreach ($video_query->posts as $vpost) {

                    $content = $vpost->post_content;
                    $video_url = null;

                    if (preg_match('/\[embed\](.*?)\[\/embed\]/i', $content, $m)) {
                        $video_url = trim($m[1]);
                    }

                    if (!$video_url && preg_match('/<iframe.*?src=["\'](.*?)["\']/i', $content, $m)) {
                        $video_url = trim($m[1]);
                    }

                    if (!$video_url && preg_match('/https?:\/\/(www\.)?(facebook|youtube|youtu\.be)[^\s"]+/i', $content, $m)) {
                        $video_url = trim($m[0]);
                    }

                    $videos[] = [
                        'post_id'   => (int) $vpost->ID,
                        'title'     => sanitize_text_field(get_the_title($vpost->ID)),
                        'video_url' => $video_url ? esc_url_raw($video_url) : null
                    ];
                }
            }

            wp_reset_postdata();
        }



        $result[] = [
            'id'          => intval($cat->term_id),
            'name' => sanitize_text_field(html_entity_decode($cat->name, ENT_QUOTES, 'UTF-8')),
            'slug'        => sanitize_key($cat->slug),
            'description' => wp_kses_post($cat->description),
            'count'       => intval($cat->count),
            'parent'      => intval($cat->parent),
            'image'       => esc_url_raw($image_url),
            'videos' => $videos

        ];
    }

    return [
        'success' => true,
        'data'    => $result
    ];
}



/**
 * Callback: Get all categories with image + placeholder
 */
/**
 * Callback: Get all regions (custom taxonomy)
 */
function myapi_get_regions(WP_REST_Request $request)
{
    $regions = get_terms([
        'taxonomy'   => 'region',   // 👈 your custom taxonomy
        'hide_empty' => false,
    ]);

    if (is_wp_error($regions)) {
        return [
            'success' => false,
            'message' => 'Failed to fetch regions'
        ];
    }

    $result = [];

    foreach ($regions as $region) {
        $result[] = [
            'id'          => (int) $region->term_id,
            'name'        => sanitize_text_field($region->name),
            'slug'        => sanitize_key($region->slug),
            'description' => wp_kses_post($region->description),
            'count'       => (int) $region->count,
            'parent'      => (int) $region->parent,
        ];
    }

    return [
        'success' => true,
        'data'    => $result
    ];
}



/**
 * Callback: Get posts by category with pagination + video url
 */
function myapi_get_posts_by_category(WP_REST_Request $request)
{
    // ==============================
    // 1. GET & SANITIZE PARAMETERS
    // ==============================
    $cat_id = absint($request->get_param('cat_id'));
    $page   = absint($request->get_param('page'));
    $ppp    = absint($request->get_param('posts_per_page'));

    if ($page <= 0) $page = 1;
    if ($ppp <= 0) $ppp = 10;

    $ppp = min($ppp, 100);
    if ($page > 500) $page = 500;

    // ==============================
    // 2. VALIDATION & CATEGORY CHECK
    // ==============================
    $category = null;

    if (!empty($cat_id)) {
        $category = get_term($cat_id, 'category');
        if (empty($category) || is_wp_error($category)) {
            return new WP_Error('invalid_category', 'Category not found', ['status' => 404]);
        }
    }

    // ==============================
    // 3. QUERY (ONLY PUBLISHED POSTS)
    // ==============================
    $args = [
        'post_type'           => 'post',
        'post_status'         => 'publish',
        'posts_per_page'      => $ppp,
        'paged'               => $page,
        'orderby'             => 'date',
        'order'               => 'DESC',
        'no_found_rows'       => false,
        'ignore_sticky_posts' => true,
        'suppress_filters'    => true,
    ];

    if (!empty($cat_id)) {
        $args['cat'] = $cat_id;
    }

    $query = new WP_Query($args);

    // ==============================
    // 4. PREPARE RESPONSE DATA
    // ==============================
    $posts = [];

    if ($query->have_posts()) {
        foreach ($query->posts as $post) {

            // 🔹 Time ago
            $modified_time = strtotime($post->post_modified);
            $now = current_time('timestamp');
            $short = str_replace(
                [' hours', ' hour', ' days', ' day', ' minutes', ' minute', ' seconds', ' second'],
                ['h', 'h', 'd', 'd', 'm', 'm', 's', 's'],
                human_time_diff($modified_time, $now)
            );

            // 🔹 Featured image
            $featured_image = get_the_post_thumbnail_url($post->ID, 'large');

            // 🔹 Categories
            $post_cats = get_the_category($post->ID);
            $post_categories = [];
            $primary_category = null;

            $api_primary_name = null;
            if (!empty($category) && !is_wp_error($category)) {
                $api_primary_name = html_entity_decode($category->name, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }

            if (!empty($post_cats)) {
                foreach ($post_cats as $cat) {

                    $decoded = html_entity_decode($cat->name, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                    $post_categories[] = $decoded;

                    // ✅ If this category is the API category, force it
                    if ($api_primary_name && $cat->term_id == $category->term_id) {
                        $primary_category = $decoded;
                    }
                }

                // ✅ Fallback: if API category not found, use first one
                if (!$primary_category && isset($post_categories[0])) {
                    $primary_category = $post_categories[0];
                }
            }

            // ==============================
            // 🎥 VIDEO URL EXTRACTION
            // ==============================
            $content = $post->post_content;
            $video_url = null;

            // [embed]URL[/embed]
            if (preg_match('/\[embed\](.*?)\[\/embed\]/i', $content, $m)) {
                $video_url = trim($m[1]);
            }

            // <iframe src="">
            if (!$video_url && preg_match('/<iframe.*?src=["\'](.*?)["\']/i', $content, $m)) {
                $video_url = trim($m[1]);
            }

            // direct fb/youtube link
            if (!$video_url && preg_match('/https?:\/\/(www\.)?(facebook|youtube|youtu\.be)[^\s"]+/i', $content, $m)) {
                $video_url = trim($m[0]);
            }

            // ==============================
            // FINAL POST OBJECT
            // ==============================
            $posts[] = [
                'id'                => (int) $post->ID,
                'category'          => $post_categories,
                'primary_category'  => $primary_category,
                'title'             => sanitize_text_field(html_entity_decode(get_the_title($post->ID))),
                'slug'              => sanitize_key($post->post_name),
                'excerpt'           => html_entity_decode(wp_trim_words(wp_strip_all_tags($post->post_content), 30), ENT_QUOTES, 'UTF-8'),
                'featured_image'    => $featured_image ? esc_url_raw($featured_image) : null,
                'video_url'         => $video_url ? esc_url_raw($video_url) : null, // ✅ NEW
                'has_video'         => $video_url ? true : false,                   // ✅ OPTIONAL (useful for app)
                'date'              => sanitize_text_field(get_the_date('M j, Y', $post->ID)),
                'updated_ago'       => $short . ' ago',
            ];
        }
    }

    wp_reset_postdata();

    // ==============================
    // 5. FINAL RESPONSE
    // ==============================
    $category_data = null;
    $decoded_category_name = html_entity_decode($category->name, ENT_QUOTES | ENT_HTML5, 'UTF-8');


    if (!empty($category)) {
        $category_data = [
            'id'   => (int) $category->term_id,
            'slug' => sanitize_key($category->slug),
            'name' => sanitize_text_field($decoded_category_name),
        ];
    }

    return new WP_REST_Response([
        'success'    => true,
        'category'   => $category_data,
        'pagination' => [
            'total_posts'    => (int) $query->found_posts,
            'total_pages'    => (int) $query->max_num_pages,
            'current_page'   => (int) $page,
            'posts_per_page' => (int) $ppp,
            'has_next_page'  => ($page < $query->max_num_pages),
        ],
        'data' => $posts
    ], 200);
}




/**
 * Get single published post
 */
function myapi_get_single_post(WP_REST_Request $request)
{

    $post_id = absint($request->get_param('post_id'));

    if (! $post_id) {
        return new WP_Error('missing_post_id', 'Post ID required', ['status' => 400]);
    }

    $post = get_post($post_id);

    if (! $post || $post->post_status !== 'publish') {
        return new WP_Error('post_not_found', 'Post not found or not published', ['status' => 404]);
    }

    // -------------------------
    // MAIN POST DATA
    // -------------------------
    $featured_image = get_the_post_thumbnail_url($post->ID, 'full');
    $cats = get_the_category($post->ID);
    $post_categories = [];
    $primary_category = null;

    if (!empty($cats)) {
        foreach ($cats as $index => $cat) {
            $decoded_cat_name = html_entity_decode($cat->name, ENT_QUOTES | ENT_HTML5, 'UTF-8');

            $post_categories[] = sanitize_text_field($decoded_cat_name);

            // First category is the primary category
            if ($index === 0) {
                $primary_category = sanitize_text_field($decoded_cat_name);
            }
        }
    }


    $post_data = [
        'id'      => (int) $post->ID,
        'title' => html_entity_decode(get_the_title($post->ID), ENT_QUOTES, 'UTF-8'),
        'content' => wp_kses_post(apply_filters('the_content', $post->post_content)),
        'date'     => sanitize_text_field(get_the_date('M j, Y', $post->ID)),
        'image'   => $featured_image ? esc_url_raw($featured_image) : null,
        'category' => $post_categories,                      // ✅ MULTIPLE CATEGORIES
        'primary_category' => $primary_category,             // ✅ PRIMARY CATEGORY
        'link'    => esc_url_raw(get_permalink($post->ID)),
    ];

    // -------------------------
    // RELATED POSTS LOGIC
    // -------------------------
    $categories = wp_get_post_categories($post_id);

    $related_posts = [];

    if (! empty($categories)) {

        $related_args = [
            'category__in'   => $categories,
            'post__not_in'   => [$post_id],
            'posts_per_page' => 10,
            'orderby'       => 'date',
            'order'         => 'DESC',
            'post_status'   => 'publish',
        ];

        $related_query = new WP_Query($related_args);

        if ($related_query->have_posts()) {
            while ($related_query->have_posts()) {
                $related_query->the_post();
                $cats = get_the_category();
                $related_categories = [];
                $primary_related_category = null;



                foreach ($cats as $index => $cat) {
                    $decoded_related_cat = html_entity_decode($cat->name, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                    $related_categories[] = sanitize_text_field($decoded_related_cat);

                    // First category is the primary category
                    if ($index === 0) {
                        $primary_related_category = sanitize_text_field($decoded_related_cat);
                    }
                }
                $thumbnail = has_post_thumbnail()
                    ? get_the_post_thumbnail_url(get_the_ID(), 'full')
                    : plugin_dir_url(__FILE__) . '/assets/images/category-placeholder.png';


                $excerpt = get_the_excerpt();
                $word_count = str_word_count(wp_strip_all_tags($excerpt));

                if ($word_count < 10) {
                    // Fallback to post content if excerpt is too short
                    $excerpt = wp_trim_words(
                        wp_strip_all_tags(get_the_content()),
                        50,
                        '...'
                    );
                } else {
                    $excerpt = wp_trim_words($excerpt, 50, '...');
                }


                $related_posts[] = [
                    'id'    => (int) get_the_ID(),
                    'title'            => sanitize_text_field(wp_trim_words(html_entity_decode(get_the_title()), 12, '...')),
                    'excerpt'          => sanitize_text_field(wp_trim_words(html_entity_decode(wp_strip_all_tags($excerpt)), 20, '...')),
                    'link'  => esc_url_raw(get_permalink()),
                    'date'     => sanitize_text_field(get_the_date('M j, Y', $post_id)),
                    'image' => esc_url_raw($thumbnail),
                    'category' => $related_categories,
                    'primary_category' => $primary_related_category,

                ];
            }
            wp_reset_postdata();
        }
    }

    // -------------------------
    // FINAL RESPONSE
    // -------------------------
    return new WP_REST_Response([
        'post'          => $post_data,
        'related_posts' => $related_posts,
    ], 200);
}




//Forgot Password API
function myapi_forgot_password(WP_REST_Request $request)
{

    $email = sanitize_email($request->get_param('email'));

    if (!email_exists($email)) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Email not registered'
        ], 404);
    }

    $user = get_user_by('email', $email);

    // 🔐 Generate 4-digit OTP
    $otp = rand(1000, 9999);

    // ⏱ OTP expiry (10 minutes)
    $expires = time() + (10 * 60);

    update_user_meta($user->ID, 'reset_otp', $otp);
    update_user_meta($user->ID, 'reset_otp_expiry', $expires);
    update_user_meta($user->ID, 'reset_otp_verified', false);

    // 📧 Send Email - Sanitize email body
    $email_body = sprintf(
        'Your OTP is: %d\nValid for 10 minutes.',
        intval($otp)
    );
    wp_mail(
        $email,
        'Password Reset OTP',
        $email_body
    );

    return new WP_REST_Response([
        'status' => true,
        'message' => 'OTP sent to email'
    ], 200);
}

function myapi_verify_otp(WP_REST_Request $request)
{

    $email = sanitize_email($request->get_param('email'));
    $otp   = sanitize_text_field($request->get_param('otp'));

    if (!email_exists($email)) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Invalid email'
        ], 404);
    }

    $user = get_user_by('email', $email);

    $saved_otp   = get_user_meta($user->ID, 'reset_otp', true);
    $otp_expiry = get_user_meta($user->ID, 'reset_otp_expiry', true);

    /**
     * 🔁 OTP EXPIRED → AUTO RESEND
     */
    if (!$saved_otp || time() > $otp_expiry) {

        // Generate NEW 4-digit OTP
        $new_otp = rand(100000, 999999);
        $expiry  = time() + (5 * 60); // 5 mins

        update_user_meta($user->ID, 'reset_otp', $new_otp);
        update_user_meta($user->ID, 'reset_otp_expiry', $expiry);
        update_user_meta($user->ID, 'reset_otp_verified', false);


        return new WP_REST_Response([
            'status' => false,
            'message' => 'OTP expired. New OTP sent to email.'
        ], 200);
    }

    /**
     * WRONG OTP
     */
    if ($otp != $saved_otp) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Invalid OTP'
        ], 400);
    }

    /**
     * ✅ OTP VERIFIED
     */
    update_user_meta($user->ID, 'reset_otp_verified', true);

    // Optional: delete OTP after verification
    delete_user_meta($user->ID, 'reset_otp');
    delete_user_meta($user->ID, 'reset_otp_expiry');

    return new WP_REST_Response([
        'status' => true,
        'message' => 'OTP verified successfully'
    ], 200);
}


function myapi_reset_password(WP_REST_Request $request)
{

    $email    = sanitize_email($request->get_param('email'));
    $password = sanitize_text_field($request->get_param('new_password'));

    if (!email_exists($email)) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Invalid email'
        ], 404);
    }

    if (strlen($password) < 6) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Password must be at least 6 characters'
        ], 400);
    }

    $user = get_user_by('email', $email);

    $verified = get_user_meta($user->ID, 'reset_otp_verified', true);

    if (!$verified) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'OTP not verified'
        ], 403);
    }

    // 🔐 Update password
    wp_set_password($password, $user->ID);

    // 🧹 Cleanup OTP data
    delete_user_meta($user->ID, 'reset_otp');
    delete_user_meta($user->ID, 'reset_otp_expiry');
    delete_user_meta($user->ID, 'reset_otp_verified');

    return new WP_REST_Response([
        'status' => true,
        'message' => 'Password reset successful'
    ], 200);
}

//Get Trending Posts
function myapi_get_trending_posts(WP_REST_Request $request)
{

    // Safety: Jetpack must exist
    if (!class_exists('Jetpack')) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Jetpack plugin not active'
        ], 500);
    }

    // Load Jetpack modules
    Jetpack::load_modules();

    // Safety: Stats function must exist
    if (!function_exists('stats_get_csv')) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Jetpack stats not enabled'
        ], 500);
    }

    // Fetch Jetpack stats
    $stats = stats_get_csv('postviews', [
        'days'  => 7,
        'limit' => 50
    ]);

    if (empty($stats)) {
        return new WP_REST_Response([
            'status' => true,
            'count'  => 0,
            'data'   => []
        ], 200);
    }

    // Pagination params
    $page = absint($request->get_param('page'));
    $raw_per_page = $request->get_param('posts_per_page');

    // If caller explicitly passed posts_per_page = 0, return ALL trending posts
    if ($raw_per_page !== null && intval($raw_per_page) === 0) {
        $per_page = 0; // special sentinel: 0 => no limit (return all)
    } else {
        $per_page = absint($raw_per_page);
        if ($page <= 0) $page = 1;
        if ($per_page <= 0) $per_page = 10;
        // Cap per-page to avoid excessive load
        $per_page = min($per_page, 50);
    }

    // Use WP current_time() so comparisons use the same timezone/reference
    $seven_days_ago = strtotime('-7 days', current_time('timestamp'));
    $posts = [];

    foreach ($stats as $item) {

        if (empty($item['post_permalink'])) {
            continue;
        }

        $post_id = url_to_postid($item['post_permalink']);

        if (!$post_id || get_post_type($post_id) !== 'post') {
            continue;
        }

        $post_date = get_post_time('U', true, $post_id);
        // Do NOT exclude posts based on their publish date here.
        // Jetpack's `postviews` with `days => 7` already limits items to recent views,
        // and excluding by publish date hides older posts that still received views.

        $author_id = get_post_field('post_author', $post_id);
        $categories = get_the_category($post_id);
        $thumbnail = get_the_post_thumbnail_url($post_id, 'full');

        // Get all category names for this post
        $post_categories = [];
        $primary_category = null;

        if (!empty($categories)) {
            foreach ($categories as $index => $cat) {
                $post_categories[] = sanitize_text_field(html_entity_decode($cat->name));

                // First category is the primary category
                if ($index === 0) {
                    $primary_category = sanitize_text_field(html_entity_decode($cat->name));
                }
            }
        }

        $posts[] = [
            'id'        => (int) $post_id,
            'title'   => sanitize_text_field(html_entity_decode(get_the_title($post_id))),
            'excerpt' => sanitize_text_field(wp_trim_words(html_entity_decode(get_the_excerpt($post_id)), 20)),

            'permalink' => esc_url_raw(get_permalink($post_id)),
            'date'     => sanitize_text_field(get_the_date('F j, Y', $post_id)),
            'timestamp' => (int) $post_date,
            'views'     => (int) $item['views'],
            'thumbnail' => $thumbnail ? esc_url_raw($thumbnail) : null,
            'author'    => [
                'id'   => (int) $author_id,
                'name' => sanitize_text_field(get_the_author_meta('display_name', $author_id)),
            ],
            // Keep `category` for backward compatibility, add `categories` (plural)
            'category'         => $post_categories,
            'primary_category' => $primary_category,
        ];
    }

    // Sort newest first
    usort($posts, function ($a, $b) {
        return $b['timestamp'] <=> $a['timestamp'];
    });

    // Pagination: slice the sorted posts array
    $total = count($posts);

    // If per_page === 0, caller asked for ALL posts — ignore pagination and return everything
    if ($per_page === 0) {
        $paged_posts = $posts;
        $total_pages = 1;
        $page = 1;
        $per_page = $total; // reflect actual returned count
    } else {
        $total_pages = $per_page > 0 ? (int) ceil($total / $per_page) : 1;
        if ($total_pages < 1) $total_pages = 1;

        $offset = ($page - 1) * $per_page;
        $paged_posts = $offset < $total ? array_slice($posts, $offset, $per_page) : [];
    }

    $response = [
        'status' => true,
        'count'  => $total,
        'data'   => $paged_posts,
        'pagination' => [
            'total'        => $total,
            'total_pages'  => $total_pages,
            'current_page' => $page,
            'per_page'     => $per_page,
            'has_next'     => $page < $total_pages,
            'has_prev'     => $page > 1,
        ],
    ];

    return new WP_REST_Response($response, 200);
}


/**
 * LOGOUT API
 */ 
function newsroomapi_logout(WP_REST_Request $request)
{

    // 🔐 Verify JWT
    $auth_header = $request->get_header('authorization');
    $jwt = '';
    if (!empty($auth_header)) {
        $jwt = trim(str_ireplace('Bearer ', '', $auth_header));
    }

    $payload = false;
    if (!empty($auth_header)) {
        $payload = newsroomapi_verify_jwt($auth_header);
    }

    // If token is invalid/expired, attempt to find user by stored token so we can still revoke it
    if ($payload === false) {
        if (empty($jwt)) {
            return new WP_REST_Response([
                'status'  => false,
                'message' => 'Invalid or expired token'
            ], 401);
        }

        $users = get_users([
            'meta_key'   => '_jwt_token',
            'meta_value' => $jwt,
            'number'     => 1,
            'fields'     => 'ID'
        ]);

        if (empty($users)) {
            return new WP_REST_Response([
                'status'  => false,
                'message' => 'Invalid or expired token'
            ], 401);
        }

        $user_id = intval($users[0]);
    } else {
        $user_id = intval($payload['sub']);

        // If we have a payload and a stored token, ensure the provided token matches stored token
        if (!empty($jwt)) {
            $stored = get_user_meta($user_id, '_jwt_token', true);
            if (!empty($stored) && !hash_equals($stored, $jwt)) {
                return new WP_REST_Response([
                    'status'  => false,
                    'message' => 'Token mismatch'
                ], 403);
            }
        }
    }

    // Ensure user exists before deleting meta
    $user = get_user_by('id', $user_id);
    if (!$user) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'User not found'
        ], 404);
    }

    // 🔄 Delete token from database
    delete_user_meta($user_id, '_jwt_token');
    delete_user_meta($user_id, '_jwt_jti');
    delete_user_meta($user_id, '_jwt_exp');

    return new WP_REST_Response([
        'status'  => true,
        'message' => 'Logged out successfully'
    ], 200);
}


/**
 * Search posts with optional pagination and category detection
 */
function myapi_search_posts(WP_REST_Request $request)
{

    // -----------------------------
    // 1. Get & sanitize input
    // -----------------------------
    $search   = sanitize_text_field($request->get_param('search'));

    // Page number
    $page_raw = $request->get_param('page');
    $page = (!empty($page_raw) && is_numeric($page_raw) && (int)$page_raw > 0) ? (int)$page_raw : 1;

    // Posts per page
    $per_page_raw = $request->get_param('posts_per_page');
    $per_page = (!empty($per_page_raw) && is_numeric($per_page_raw) && (int)$per_page_raw > 0) ? (int)$per_page_raw : 10;

    // Validate search
    if (empty($search)) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Provide search parameter'
        ], 400);
    }

    // -----------------------------
    // 2. Auto-detect category from search
    // -----------------------------
    $matched_category = null;

    $terms = get_terms([
        'taxonomy'   => 'category',
        'hide_empty' => false,
        'search'     => $search,
        'number'     => 1,
    ]);

    if (!empty($terms) && !is_wp_error($terms)) {
        $term = $terms[0];
        $decoded_term_name = html_entity_decode($term->name, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        $matched_category = [
            'id'    => $term->term_id,
            'name'  => sanitize_text_field($decoded_term_name),
            'slug'  => $term->slug,
            'count' => (int) $term->count,
        ];
    }

    // -----------------------------
    // 3. WP Query
    // -----------------------------
    $args = [
        'post_type'      => 'post',
        'post_status'    => 'publish',
        's'              => $search,
        'posts_per_page' => $per_page,
        'paged'          => $page,
    ];

    // Filter by matched category
    if ($matched_category) {
        $args['tax_query'] = [
            [
                'taxonomy' => 'category',
                'field'    => 'term_id',
                'terms'    => $matched_category['id'],
            ]
        ];
    }


    $query = new WP_Query($args);
    $posts = [];

    if ($query->have_posts()) {
        while ($query->have_posts()) {
            $query->the_post();

            // Get ALL category names for this post and determine primary
            $post_cats = get_the_category(get_the_ID());
            $category_names = [];
            $primary_category = null;

            if (!empty($post_cats) && !is_wp_error($post_cats)) {
                foreach ($post_cats as $index => $cat) {
                    $decoded_cat = html_entity_decode($cat->name, ENT_QUOTES | ENT_HTML5, 'UTF-8');

                    $category_names[] = sanitize_text_field($decoded_cat);
                    if ($index === 0) {
                        $primary_category = sanitize_text_field($decoded_cat);
                    }
                }
            }


            // Calculate reading time
            $content = get_post_field('post_content', get_the_ID());
            $word_count = str_word_count(strip_tags($content));
            $reading_time = ceil($word_count / 200);

            // Get raw date to avoid theme filters/HTML injection
            $post_date = get_post_field('post_date', get_the_ID());
            $clean_date = date('M j, Y', strtotime($post_date));

            $formatted_date = $clean_date . ' ' . $reading_time . ' Mins Read';

            $posts[] = [
                'id'      => get_the_ID(),
                'title'   => sanitize_text_field(wp_trim_words(html_entity_decode(get_the_title()), 12, '...')),
                'excerpt' => sanitize_text_field(wp_trim_words(html_entity_decode(wp_strip_all_tags(get_the_excerpt())), 30, '...')),
                'image'   => get_the_post_thumbnail_url(get_the_ID(), 'full'),
                'date'     => $formatted_date,
                'categories'       => $category_names, // 👈 ALL categories
                'primary_category' => $primary_category,
            ];
        }
        wp_reset_postdata();
    }

    // -----------------------------
    // 4. Prepare response
    // -----------------------------
    return new WP_REST_Response([
        'status'        => true,
        'search'        => $search,
        'category'      => $matched_category,       // null if no match
        'total_posts'   => (int) $query->found_posts,
        'total_pages'   => (int) $query->max_num_pages,
        'current_page'  => $page,
        'posts_per_page' => $per_page,
        'data'          => $posts,
    ], 200);
}







/**
 * Get User Profile API
 */
function myapi_get_user_profile(WP_REST_Request $request)
{
    // 🔐 Verify JWT
    $payload = newsroomapi_verify_jwt(
        $request->get_header('authorization')
    );

    if (!$payload) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Invalid or expired token'
        ], 401);
    }

    $user_id = intval($payload['sub']);

    // 🔍 Get user
    $user = get_user_by('ID', $user_id);

    if (!$user) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'User not found'
        ], 404);
    }

    // 📦 Get user meta
    $phone               = get_user_meta($user_id, 'phone', true);
    $selected_categories = get_user_meta($user_id, 'selected_category', true);
    $selected_regions    = get_user_meta($user_id, 'selected_region', true);
    $profile_image       = get_user_meta($user_id, 'profile_image', true);

    // Normalize selected regions
    if (is_string($selected_regions) && strpos($selected_regions, ',') !== false) {
        $selected_regions = array_filter(array_map('trim', explode(',', $selected_regions)));
    } elseif (is_numeric($selected_regions)) {
        $selected_regions = [$selected_regions];
    } elseif (!is_array($selected_regions)) {
        $selected_regions = [];
    }

    $selected_regions = array_map('absint', (array) $selected_regions);
    $selected_regions = array_filter($selected_regions);

    // Convert category IDs to names
    $interest_names = [];
    if (is_array($selected_categories) && !empty($selected_categories)) {
        foreach ($selected_categories as $cat_id) {
            $term = get_term(absint($cat_id), 'category');
            if ($term && !is_wp_error($term)) {
                $interest_names[] = [
                    'id'   => (int) $term->term_id,
                    'name' => sanitize_text_field($term->name),
                    'slug' => sanitize_key($term->slug),
                ];
            }
        }
    }

    // Convert region IDs to names
    $region_names = [];
    if (is_array($selected_regions) && !empty($selected_regions)) {
        foreach ($selected_regions as $region_id) {
            $term = get_term(absint($region_id), 'region');
            if ($term && !is_wp_error($term)) {
                $region_names[] = [
                    'id'   => (int) $term->term_id,
                    'name' => sanitize_text_field($term->name),
                    'slug' => sanitize_key($term->slug),
                ];
            }
        }
    }

    return new WP_REST_Response([
        'status' => true,
        'data'   => [
            'id'         => $user->ID,
            'first_name' => $user->first_name,
            'last_name'  => $user->last_name,
            'full_name'  => trim($user->first_name . ' ' . $user->last_name),
            'username'   => $user->user_login, // read-only
            'email'      => $user->user_email,
            'phone'      => $phone ?: '',
            'interests'  => $interest_names,
            'selected_region' => $region_names,
            'profile_image' => $profile_image ?: ''
        ]
    ], 200);
}


/**
 * Videos API
 */
function myapi_get_latest_videos(WP_REST_Request $request)
{

    // Page number
    $page = max(1, (int) $request->get_param('page'));

    // post_per_page with default fallback
    $post_per_page = (int) $request->get_param('post_per_page');
    if ($post_per_page <= 0) {
        $post_per_page = 10;
    }
    $category = 'video'; // slug of video category

    $args = [
        'post_type'      => 'post',
        'posts_per_page' => $post_per_page,
        'paged'          => $page,
        'category_name'  => $category,
        'post_status'    => 'publish'
    ];

    $query = new WP_Query($args);

    if (!$query->have_posts()) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'No videos found'
        ], 200);
    }

    $videos = [];

    foreach ($query->posts as $post) {

        $content = $post->post_content;

        // Extract embed URL
        preg_match('/\[embed\](.*?)\[\/embed\]/', $content, $matches);

        if (!empty($matches[1])) {
            $video_url = esc_url($matches[1]);
            $thumbnail = get_the_post_thumbnail_url($post->ID, 'full');
            // 2️⃣ Fallback to YouTube thumbnail
            if (!$thumbnail) {
                $thumbnail = myapi_get_video_thumbnail($video_url);
            }
            // Get all category names for this post
            $post_cats = get_the_category($post->ID);
            $post_categories = [];
            $primary_category = null;

            if (!empty($post_cats)) {
                foreach ($post_cats as $index => $cat) {

                    $post_categories[] = sanitize_text_field(html_entity_decode($cat->name));

                    // First category is the primary category
                    if ($index === 0) {
                        $primary_category = sanitize_text_field(html_entity_decode($cat->name));
                    }
                }
            }

            $videos[] = [
                'post_id'    => $post->ID,
                'title' => sanitize_text_field(html_entity_decode(get_the_title($post->ID))),
                'video_url'  => esc_url($matches[1]),
                'thumbnail'  => esc_url($thumbnail),
                'excerpt'    => wp_trim_words(strip_tags($content), 30),
                'category'   => $post_categories,
                'primary_category' => $primary_category,
            ];
        }
    }

    return new WP_REST_Response([
        'status'      => true,
        'page'        => $page,
        'posts_per_page' => $post_per_page,
        'total_posts' => (int) $query->found_posts,
        'total_pages' => (int) $query->max_num_pages,
        'videos'      => $videos
    ], 200);
}


/**
 * Save or unsave a post for the authenticated user.
 * Toggles presence of the post ID in user meta key `saved_posts`.
 */
function myapi_save_posts(WP_REST_Request $request)
{

    // Verify JWT
    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));

    if (!$payload) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Invalid or expired token'
        ], 401);
    }

    $user_id = intval($payload['sub']);
    // Only allow a single post_id at a time
    if ($request->get_param('post_ids') !== null) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Only a single post_id allowed. Use /remove-saved-post for removals.'
        ], 400);
    }

    $post_id = absint($request->get_param('post_id'));
    if (!$post_id) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'post_id required and must be a valid integer'
        ], 400);
    }

    $post = get_post($post_id);
    if (!$post || $post->post_status !== 'publish') {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Post not found or not published'
        ], 404);
    }

    $saved = get_user_meta($user_id, 'saved_posts', true);
    if (!is_array($saved)) {
        $saved = [];
    }
    $saved = array_map('intval', $saved);

    if (in_array($post_id, $saved, true)) {
        return new WP_REST_Response([
            'status'      => true,
            'message'     => 'Post already saved',
            'saved_posts' => $saved
        ], 200);
    }

    $saved[] = $post_id;
    $saved = array_values(array_unique($saved));
    update_user_meta($user_id, 'saved_posts', $saved);

    return new WP_REST_Response([
        'status'      => true,
        'message'     => 'Post saved',
        'saved_posts' => $saved
    ], 200);
}


/**
 * Remove one or more saved post IDs for the authenticated user.
 */
function myapi_remove_saved_posts(WP_REST_Request $request)
{

    // Verify JWT
    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));

    if (!$payload) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Invalid or expired token'
        ], 401);
    }

    $user_id = intval($payload['sub']);

    // Only allow a single post_id at a time
    if ($request->get_param('post_ids') !== null) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Only a single post_id allowed for removal. Use /save-post to add.'
        ], 400);
    }

    $post_id = absint($request->get_param('post_id'));
    if (!$post_id) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'post_id required and must be a valid integer'
        ], 400);
    }

    $saved = get_user_meta($user_id, 'saved_posts', true);
    if (!is_array($saved)) {
        $saved = [];
    }
    $saved = array_map('intval', $saved);

    if (!in_array($post_id, $saved, true)) {
        return new WP_REST_Response([
            'status'      => true,
            'message'     => 'Post not in saved list',
            'saved_posts' => $saved
        ], 200);
    }

    $saved = array_values(array_diff($saved, [$post_id]));
    update_user_meta($user_id, 'saved_posts', $saved);

    return new WP_REST_Response([
        'status'      => true,
        'message'     => 'Post removed from saved list',
        'saved_posts' => $saved
    ], 200);
}


/**
 * Show all saved posts for authenticated user
 */
function myapi_show_all_saved_posts(WP_REST_Request $request)
{

    // Verify JWT
    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));

    if (!$payload) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Invalid or expired token'
        ], 401);
    }

    $user_id = intval($payload['sub']);

    $saved = get_user_meta($user_id, 'saved_posts', true);
    if (!is_array($saved)) {
        $saved = [];
    }

    $result = [];

    foreach ($saved as $pid) {
        $pid = absint($pid);
        if (!$pid) continue;

        $post = get_post($pid);
        if (!$post || $post->post_status !== 'publish') continue;

        // Get category name
        $cats = get_the_category($post->ID);
        $category_name = null;
        if (!empty($cats)) {
            $cat_name = html_entity_decode($cats[0]->name, ENT_QUOTES, 'UTF-8');
            $category_name = sanitize_text_field($cat_name);
        }

        $result[] = [
            'id'      => (int) $post->ID,
            'title' => sanitize_text_field(html_entity_decode(get_the_title($post->ID))),
            'excerpt' => sanitize_text_field(
                html_entity_decode(
                    wp_trim_words(wp_strip_all_tags($post->post_content), 30)
                )
            ),
            'image'   => get_the_post_thumbnail_url($post->ID, 'full') ? esc_url_raw(get_the_post_thumbnail_url($post->ID, 'full')) : null,
            'date'     => sanitize_text_field(get_the_date('M j, Y', $post->ID)),
            'link'    => esc_url_raw(get_permalink($post->ID)),
            'category' => $category_name,
        ];
    }

    return new WP_REST_Response([
        'status'      => true,
        'count'       => count($result),
        'saved_posts' => $saved,
        'data'        => $result
    ], 200);
}




/**
 * Save user selected category & region (with decoded names)
 */
function myapi_save_user_selection(WP_REST_Request $request)
{
    // 1️⃣ Verify JWT
    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));

    if (!is_array($payload) || empty($payload['sub'])) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Unauthorized'
        ], 401);
    }

    $user_id = absint($payload['sub']);

    // 2️⃣ Accept categories and regions (array, CSV, or single)
    $raw_categories = $request->get_param('category_ids') ?? $request->get_param('category_id');
    $raw_regions    = $request->get_param('region_ids') ?? $request->get_param('region_id');

    // Process categories
    $category_ids = [];
    if (is_array($raw_categories)) {
        $category_ids = array_map('absint', $raw_categories);
    } elseif (is_string($raw_categories) && strpos($raw_categories, ',') !== false) {
        $category_ids = array_map('absint', array_filter(array_map('trim', explode(',', $raw_categories))));
    } elseif (is_numeric($raw_categories)) {
        $category_ids = [absint($raw_categories)];
    }

    // Process regions
    $region_ids = [];
    if (is_array($raw_regions)) {
        $region_ids = array_map('absint', $raw_regions);
    } elseif (is_string($raw_regions) && strpos($raw_regions, ',') !== false) {
        $region_ids = array_map('absint', array_filter(array_map('trim', explode(',', $raw_regions))));
    } elseif (is_numeric($raw_regions)) {
        $region_ids = [absint($raw_regions)];
    }

    // Clean arrays
    $category_ids = array_values(array_unique(array_filter($category_ids)));
    $region_ids   = array_values(array_unique(array_filter($region_ids)));

    // 3️⃣ Save in user meta
    if (!empty($category_ids)) {
        update_user_meta($user_id, 'selected_category', $category_ids);
    } else {
        delete_user_meta($user_id, 'selected_category');
    }

    if (!empty($region_ids)) {
        update_user_meta($user_id, 'selected_region', $region_ids);
    } else {
        delete_user_meta($user_id, 'selected_region');
    }

    // 4️⃣ Get decoded category names for API response
    $categories = [];
    foreach ($category_ids as $cat_id) {
        $term = get_term($cat_id);
        if ($term && !is_wp_error($term)) {
            $categories[] = [
                'id' => $term->term_id,
                'name' => html_entity_decode($term->name, ENT_QUOTES | ENT_HTML5, 'UTF-8')
            ];
        }
    }

    $regions = [];
    foreach ($region_ids as $reg_id) {
        $term = get_term($reg_id);
        if ($term && !is_wp_error($term)) {
            $regions[] = [
                'id' => $term->term_id,
                'name' => html_entity_decode($term->name, ENT_QUOTES | ENT_HTML5, 'UTF-8')
            ];
        }
    }

    // 5️⃣ Return response with decoded names
    return new WP_REST_Response([
        'status' => true,
        'message' => 'Category / Region saved successfully',
        'selected_category' => $categories,
        'selected_region' => $regions
    ], 200);
}






/**
 * My News – Posts based on user's preferred category & region
 */
/**
 * Extract video URL from post content (embed/iframe/direct link)
 */
function myapi_extract_video_url_from_content($content) {
    $video_url = null;

    if (preg_match('/\[embed\](.*?)\[\/embed\]/i', $content, $m)) {
        $video_url = trim($m[1]);
    }

    if (!$video_url && preg_match('/<iframe.*?src=["\'](.*?)["\']/i', $content, $m)) {
        $video_url = trim($m[1]);
    }

    if (!$video_url && preg_match('/https?:\/\/(www\.)?(facebook|youtube|youtu\.be)[^\s"]+/i', $content, $m)) {
        $video_url = trim($m[0]);
    }

    return $video_url ? esc_url_raw($video_url) : null;
}

function myapi_get_recommended_posts(WP_REST_Request $request)
{
    // 🔐 Verify JWT
    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));

    if (!is_array($payload) || empty($payload['sub'])) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Unauthorized'
        ], 401);
    }

    $user_id = absint($payload['sub']);

    // Number of posts to return per category (defaults to 5)
    $posts_per_category = absint($request->get_param('posts_per_category'));
    if ($posts_per_category <= 0) {
        $posts_per_category = 5;
    }

    // Fetch user preferences (expect arrays)
    $category_ids = get_user_meta($user_id, 'selected_category', true);
    $region_ids   = get_user_meta($user_id, 'selected_region', true);

    if (empty($category_ids) || !is_array($category_ids)) {
        return new WP_REST_Response([
            'status'  => true,
            'message' => 'No categories selected',
            'data'    => []
        ], 200);
    }

    $result = [];

    foreach ($category_ids as $cat_id) {
        $cat_id = absint($cat_id);
        if (!$cat_id) continue;

        $term = get_term($cat_id, 'category');
        if (!$term || is_wp_error($term)) continue;

        $args = [
            'post_type'      => 'post',
            'post_status'    => 'publish',
            'posts_per_page' => $posts_per_category,
            'orderby'        => 'date',
            'order'          => 'DESC',
            'no_found_rows'  => false,
            'cat'            => $cat_id,
        ];

        // If regions present, restrict posts to those regions as well
        if (!empty($region_ids) && is_array($region_ids)) {
            $args['tax_query'] = [
                [
                    'taxonomy' => 'region',
                    'field'    => 'term_id',
                    'terms'    => $region_ids,
                ]
            ];
        }

        $query = new WP_Query($args);

        $posts = [];
        $final_query = $query;

        // If region filter present but returns no posts, fallback to category-only query
        if ((!empty($region_ids) && is_array($region_ids)) && !$query->have_posts()) {
            $fallback_args = $args;
            unset($fallback_args['tax_query']);
            $final_query = new WP_Query($fallback_args);
        }

        if ($final_query->have_posts()) {
            foreach ($final_query->posts as $post) {

                // Categories
                $post_cats = get_the_category($post->ID);
                $post_categories = [];
                $primary_category = null;

                if (!empty($post_cats)) {
                    foreach ($post_cats as $index => $cat) {
                        $post_categories[] = sanitize_text_field(html_entity_decode($cat->name));

                        if ($index === 0) {
                            $primary_category = sanitize_text_field(html_entity_decode($cat->name));
                        }
                    }
                }

                // ✅ Video URL (only if post is in Video category)
                $is_video = has_category('video', $post->ID) || has_category(2189, $post->ID);
                $video_url = $is_video ? myapi_extract_video_url_from_content($post->post_content) : null;

                $posts[] = [
                    'id'        => (int) $post->ID,
                    'title'     => sanitize_text_field(html_entity_decode(get_the_title($post->ID))),
                    'excerpt'   => sanitize_text_field(wp_trim_words(html_entity_decode(wp_strip_all_tags($post->post_content)), 30)),
                    'thumbnail' => get_the_post_thumbnail_url($post->ID, 'full') ? esc_url_raw(get_the_post_thumbnail_url($post->ID, 'full')) : null,
                    'link'      => esc_url_raw(get_permalink($post->ID)),
                    'video_url' => $video_url,           // ✅ ADDED
                    'is_video'  => (bool) $is_video,     // ✅ optional but helpful
                    'date'      => sanitize_text_field(get_the_date('M j, Y', $post->ID)),
                    'category'  => $post_categories,
                    'primary_category' => $primary_category,
                ];
            }

            $found_posts = (int) $final_query->found_posts;
            wp_reset_postdata();
        } else {
            $found_posts = 0;
        }

        $result[] = [
            'category_id'   => (int) $term->term_id,
            'category_name' => sanitize_text_field(html_entity_decode($term->name)),
            'post_count'    => $found_posts,
            'posts'         => $posts,
        ];
    }

    if (empty($result)) {
        return new WP_REST_Response([
            'status'  => true,
            'message' => 'No news found for selected categories',
            'data'    => []
        ], 200);
    }

    return new WP_REST_Response([
        'status'              => true,
        'posts_per_category'  => $posts_per_category,
        'categories_returned' => count($result),
        'data'                => $result,
    ], 200);
}


// Notification API callback
function myapi_get_notification(WP_REST_Request $request)
{

    // Posts per page
    $per_page_raw = $request->get_param('posts_per_page');
    $per_page = (!empty($per_page_raw) && is_numeric($per_page_raw) && (int)$per_page_raw > 0) ? (int)$per_page_raw : 5;

    // Query latest posts
    $args = [
        'post_type'      => 'post',
        'post_status'    => 'publish',
        'posts_per_page' => $per_page,
        'orderby'        => 'date',
        'order'          => 'DESC',
    ];

    $query = new WP_Query($args);
    $notifications = [];

    if ($query->have_posts()) {
        foreach ($query->posts as $post) {
            $categories = wp_get_post_terms($post->ID, 'category', ['fields' => 'names']);

            $notifications[] = [
                'id'       => (int) $post->ID,
                'title' => sanitize_text_field(html_entity_decode(get_the_title($post->ID))),
                'excerpt' => sanitize_text_field(
                    wp_trim_words(
                        html_entity_decode($post->post_excerpt ?: wp_strip_all_tags($post->post_content)),
                        20,
                        '...'
                    )
                ),
                'image'    => get_the_post_thumbnail_url($post->ID, 'full') ?: null,
                'date'     => sanitize_text_field(get_the_date('M j, Y', $post->ID)),
                'categories' => $categories,
                'link'     => esc_url_raw(get_permalink($post->ID)),
            ];
        }
        wp_reset_postdata();
    }

    return new WP_REST_Response([
        'status' => true,
        'notifications' => $notifications,
    ], 200);
}


// Save post to Continue Reading
function myapi_continue_reading_post(WP_REST_Request $request)
{

    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));
    if (!is_array($payload) || empty($payload['sub'])) {
        return new WP_REST_Response(['status' => false, 'message' => 'Unauthorized'], 401);
    }

    $user_id = absint($payload['sub']);
    $post_id = absint($request->get_param('post_id'));
    $progress = absint($request->get_param('progress'));

    // Validate post exists and is published
    $post = get_post($post_id);
    if (!$post || $post->post_status !== 'publish') {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Post not found or not published'
        ], 404);
    }

    // Clamp progress to 0-100
    $progress = max(0, min(100, $progress));

    // Get existing continue_reading meta (associative array)
    $continue_reading = get_user_meta($user_id, 'continue_reading', true);
    if (!is_array($continue_reading)) {
        $continue_reading = [];
    }

    // If progress >= 100, mark as complete (remove from list)
    if ($progress >= 100) {
        unset($continue_reading[$post_id]);
        update_user_meta($user_id, 'continue_reading', $continue_reading);
        return new WP_REST_Response([
            'status' => true,
            'message' => 'Post marked as complete',
            'post_id' => $post_id,
            'progress' => 100,
            'total_continue_posts' => count($continue_reading)
        ], 200);
    }

    // Otherwise, save/update progress
    $continue_reading[$post_id] = [
        'progress' => intval($progress),
        'updated' => intval(current_time('timestamp'))
    ];

    // Clean array: remove any non-associative or invalid entries
    $cleaned = [];
    foreach ($continue_reading as $pid => $data) {
        $pid = intval($pid);
        if ($pid > 0 && is_array($data)) {
            $cleaned[$pid] = [
                'progress' => intval($data['progress'] ?? 0),
                'updated' => intval($data['updated'] ?? 0)
            ];
        }
    }

    update_user_meta($user_id, 'continue_reading', $cleaned);

    return new WP_REST_Response([
        'status' => true,
        'message' => 'Reading progress saved',
        'post_id' => $post_id,
        'progress' => $progress,
        'total_continue_posts' => count($continue_reading)
    ], 200);
}




function myapi_get_continue_reading(WP_REST_Request $request)
{
    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));
    if (!is_array($payload) || empty($payload['sub'])) {
        return new WP_REST_Response(['status' => false, 'message' => 'Unauthorized'], 401);
    }

    $user_id = absint($payload['sub']);

    // Get continue_reading meta
    $continue_reading = get_user_meta($user_id, 'continue_reading', true);
    if (!is_array($continue_reading) || empty($continue_reading)) {
        return new WP_REST_Response([
            'status' => true,
            'message' => 'No continue reading posts',
            'posts' => []
        ], 200);
    }

    // Sort by updated timestamp (latest first)
    uasort($continue_reading, function ($a, $b) {
        return ($b['updated'] ?? 0) <=> ($a['updated'] ?? 0);
    });

    $posts = [];
    foreach ($continue_reading as $post_id => $data) {
        $post_id = absint($post_id);
        $post = get_post($post_id);

        // Skip if post doesn't exist or not published
        if (!$post || $post->post_status !== 'publish') {
            continue;
        }

        $progress = absint($data['progress'] ?? 0);
        $updated = $data['updated'] ?? 0;

        // Get all category names for this post
        $post_cats = get_the_category($post->ID);
        $post_categories = [];
        $primary_category = null;

        if (!empty($post_cats)) {
            foreach ($post_cats as $index => $cat) {
                $post_categories[] = sanitize_text_field($cat->name);

                // First category is the primary category
                if ($index === 0) {
                    $primary_category = sanitize_text_field($cat->name);
                }
            }
        }

        $posts[] = [
            'id' => (int) $post->ID,
            'title'   => sanitize_text_field(html_entity_decode(get_the_title($post->ID))),
            'excerpt' => sanitize_text_field(
                wp_trim_words(
                    html_entity_decode($post->post_excerpt ?: wp_strip_all_tags($post->post_content)),
                    30,
                    '...'
                )
            ),
            'image' => get_the_post_thumbnail_url($post->ID, 'full') ? esc_url_raw(get_the_post_thumbnail_url($post->ID, 'full')) : null,
            'date'     => sanitize_text_field(get_the_date('M j, Y', $post->ID)),
            'progress' => $progress,
            'updated' => (int) $updated,
            'link' => esc_url_raw(get_permalink($post->ID)),
            'category'        => $post_categories,
            'primary_category' => $primary_category,
        ];
    }

    return new WP_REST_Response([
        'status' => true,
        'message' => count($posts) > 0 ? 'Continue reading posts found' : 'No valid continue reading posts',
        'posts' => $posts
    ], 200);
}

/**
 * Delete a post from Continue Reading
 */
function myapi_delete_continue_reading(WP_REST_Request $request)
{

    // 🔐 Verify JWT
    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));
    if (!is_array($payload) || empty($payload['sub'])) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Unauthorized'
        ], 401);
    }

    $user_id = absint($payload['sub']);
    $post_id = absint($request->get_param('post_id'));

    if (!$post_id) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Post ID is required'
        ], 400);
    }

    // Get continue_reading meta
    $continue_reading = get_user_meta($user_id, 'continue_reading', true);
    if (!is_array($continue_reading) || empty($continue_reading)) {
        return new WP_REST_Response([
            'status' => true,
            'message' => 'Nothing to delete'
        ], 200);
    }

    // If post not found
    if (!isset($continue_reading[$post_id])) {
        return new WP_REST_Response([
            'status' => true,
            'message' => 'Post already removed'
        ], 200);
    }

    // Remove post
    unset($continue_reading[$post_id]);

    // Update meta
    update_user_meta($user_id, 'continue_reading', $continue_reading);

    return new WP_REST_Response([
        'status' => true,
        'message' => 'Continue reading entry deleted',
        'post_id' => $post_id,
        'total_continue_posts' => count($continue_reading)
    ], 200);
}


// Feedback API

function myapi_create_feedback_table()
{
    global $wpdb;
    $table_name = $wpdb->prefix . 'user_feedback';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT(20) UNSIGNED DEFAULT 0,
        name VARCHAR(100),
        email VARCHAR(100),
        message TEXT NOT NULL,
        category TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
    ) $charset_collate;";


    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}
add_action('after_setup_theme', 'myapi_create_feedback_table');




function myapi_save_feedback_authenticated(WP_REST_Request $request)
{
    global $wpdb;
    $table_name = $wpdb->prefix . 'user_feedback';

    // Get JWT token from Authorization header
    $auth_header = $request->get_header('authorization');
    if (!$auth_header) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Authorization header missing'
        ], 401);
    }

    if (stripos($auth_header, 'Bearer ') === 0) {
        $auth_header = trim(str_ireplace('Bearer ', '', $auth_header));
    }

    // 🔐 Verify JWT
    $payload = newsroomapi_verify_jwt(
        $request->get_header('authorization')
    );

    if (!$payload) {
        return new WP_REST_Response([
            'status'  => false,
            'message' => 'Invalid or expired token'
        ], 401);
    }

    $user_id = intval($payload['sub']);

    // Sanitize inputs
    $name    = sanitize_text_field($request->get_param('name'));
    $email   = sanitize_email($request->get_param('email'));
    $message = sanitize_textarea_field($request->get_param('message'));
    $category  = sanitize_textarea_field($request->get_param('category'));

    if (empty($message)) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'Feedback message is required'
        ], 400);
    }

    // Insert into database
    $wpdb->insert(
        $table_name,
        [
            'user_id'    => $user_id,
            'name'       => $name,
            'email'      => $email,
            'message'    => $message,
            'category'   => $category ?: null,
            'created_at' => current_time('mysql'),
        ]
    );

    return new WP_REST_Response([
        'status' => true,
        'message' => 'Feedback submitted successfully',
        'user_id_saved' => $user_id
    ], 200);
}

// USER Settings GET API
function myapi_get_user_settings(WP_REST_Request $request)
{

    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));
    if (!is_array($payload) || empty($payload['sub'])) {
        return new WP_REST_Response(['status' => false, 'message' => 'Unauthorized'], 401);
    }
    // 🔐 Privacy Policy Page
    $privacy_page_id = get_page_by_path('privacy-policy');
    $privacy_page_url = $privacy_page_id ? get_permalink($privacy_page_id) : '';

    $user_id = absint($payload['sub']);

    return new WP_REST_Response([
        'status' => true,
        'settings' => [
            'notifications_enabled'   => (bool) get_user_meta($user_id, 'notifications_enabled', true),
            'video_autoplay'          => (bool) get_user_meta($user_id, 'video_autoplay', true),
            'article_video_autoplay'  => (bool) get_user_meta($user_id, 'article_video_autoplay', true),
            'privacy_policy_url' => $privacy_page_url
        ]
    ], 200);
}

// USER Settings SAVE API
function myapi_save_user_settings(WP_REST_Request $request)
{

    $payload = newsroomapi_verify_jwt($request->get_header('authorization'));
    if (!is_array($payload) || empty($payload['sub'])) {
        return new WP_REST_Response(['status' => false, 'message' => 'Unauthorized'], 401);
    }

    $user_id = absint($payload['sub']);

    // Read boolean params safely
    $notifications_enabled = filter_var($request->get_param('notifications_enabled'), FILTER_VALIDATE_BOOLEAN);
    $video_autoplay         = filter_var($request->get_param('video_autoplay'), FILTER_VALIDATE_BOOLEAN);
    $article_video_autoplay = filter_var($request->get_param('article_video_autoplay'), FILTER_VALIDATE_BOOLEAN);

    // Save user meta
    update_user_meta($user_id, 'notifications_enabled', $notifications_enabled);
    update_user_meta($user_id, 'video_autoplay', $video_autoplay);
    update_user_meta($user_id, 'article_video_autoplay', $article_video_autoplay);

    return new WP_REST_Response([
        'status' => true,
        'message' => 'Settings updated successfully',
        'saved' => [
            'notifications_enabled'   => $notifications_enabled,
            'video_autoplay'          => $video_autoplay,
            'article_video_autoplay'  => $article_video_autoplay
        ]
    ], 200);
}





//PUSH NOTIFICATION REQUEST
/**
 * Dynamic Firebase Push Notification API for WordPress
 */

// ===============================
// 🔔 FIREBASE PUSH NOTIFICATION
// ===============================


/**
 * 1️⃣ Get Firebase Access Token
 */
function getFirebaseAccessToken()
{

    $jsonFile = plugin_dir_path(__FILE__) . 'firebase-service-account.json';

    if (!file_exists($jsonFile)) return false;

    $json = json_decode(file_get_contents($jsonFile), true);
    $now = time();

    $header = ['alg' => 'RS256', 'typ' => 'JWT'];
    $claim = [
        'iss'   => $json['client_email'],
        'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
        'aud'   => $json['token_uri'],
        'iat'   => $now,
        'exp'   => $now + 3600
    ];

    $jwtHeader = rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=');
    $jwtClaim  = rtrim(strtr(base64_encode(json_encode($claim)), '+/', '-_'), '=');
    $signingInput = "$jwtHeader.$jwtClaim";

    openssl_sign($signingInput, $signature, openssl_pkey_get_private($json['private_key']), "SHA256");
    $jwtSignature = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');

    $jwt = "$jwtHeader.$jwtClaim.$jwtSignature";

    $ch = curl_init($json['token_uri']);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_POSTFIELDS => http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion'  => $jwt
        ])
    ]);

    $response = curl_exec($ch);
    curl_close($ch);

    $data = json_decode($response, true);
    return $data['access_token'] ?? false;
}


/**
 * 2️⃣ Send push to ALL users (topic: all_news)
 */
function sendAllNewsNotification($title, $body, $data = [])
{

    $accessToken = getFirebaseAccessToken();
    if (!$accessToken) {
        return "Failed to get access token";
    }

    $projectId = "news-room-9bb54"; // your firebase project id

    $payload = [
        "message" => [
            "topic" => "all_news",
            "notification" => [
                "title" => $title,
                "body"  => $body,
            ],
            "data" => array_map('strval', $data)
        ]
    ];

    $ch = curl_init("https://fcm.googleapis.com/v1/projects/$projectId/messages:send");
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            "Authorization: Bearer $accessToken",
            "Content-Type: application/json"
        ],
        CURLOPT_POSTFIELDS => json_encode($payload),
    ]);

    $response = curl_exec($ch);
    curl_close($ch);

    return $response;
}


/**
 * 3️⃣ REST API Endpoint
 */
add_action('rest_api_init', function () {
    register_rest_route('myapi/v1', '/push', [
        'methods'  => 'POST',
        'callback' => 'handlePushNotificationRequest',
        'permission_callback' => '__return_true',
    ]);
});


/**
 * 4️⃣ API Handler (NO device token)
 */
function handlePushNotificationRequest(WP_REST_Request $request)
{

    $title = sanitize_text_field($request->get_param('title'));
    $body  = sanitize_text_field($request->get_param('body'));
    $data  = $request->get_param('data') ?: [];

    if (!$title) {
        return new WP_REST_Response([
            'status' => false,
            'message' => 'title and body are required'
        ], 400);
    }

    $result = sendAllNewsNotification($title, $body, $data);

    return new WP_REST_Response([
        'status' => true,
        'result' => json_decode($result, true)
    ]);
}

// 🔔 Auto push notification when a post is published
add_action('publish_post', function ($post_id, $post) {

    // Avoid sending notification for auto-saves
    if (wp_is_post_revision($post_id)) return;

    $title = get_the_title($post_id);
    $body  = wp_trim_words($post->post_content, 20); // short snippet
    $data  = ['post_id' => $post_id];

    // Call your push function
    sendAllNewsNotification($title, $body, $data);
}, 10, 2);




/**
 * Delete User API (Soft or Hard delete)
 */
function myapi_delete_account(WP_REST_Request $request)
{
    // 1️⃣ Get the JWT from Authorization header
    $auth_header = $request->get_header('authorization');

    if (!$auth_header) {
        return [
            'status' => false,
            'message' => 'Authorization header missing'
        ];
    }

    // 2️⃣ Verify JWT
    $payload = newsroomapi_verify_jwt($auth_header);

    if (!$payload || empty($payload['sub'])) {
        return [
            'status' => false,
            'message' => 'Invalid or expired token'
        ];
    }

    $user_id = intval($payload['sub']);

    // 3️⃣ Soft delete (mark user as deleted instead of removing completely)
    update_user_meta($user_id, 'is_deleted', 1);
    update_user_meta($user_id, 'deleted_at', time());

    // 4️⃣ Invalidate JWT sessions by clearing stored tokens
    delete_user_meta($user_id, '_jwt_token');
    delete_user_meta($user_id, '_jwt_jti');
    delete_user_meta($user_id, '_jwt_exp');

    return [
        'status' => true,
        'message' => 'User account deleted successfully'
    ];
}


//admap advert List dropdown
function newsroom_get_ad_placements()
{
    $placements = [
        [
            "id" => "bottom_bar_sticky",
            "label" => "Bottom Bar Sticky Ad"
        ],
        [
            "id" => "home_popup",
            "label" => "Home page pop up ad"
        ],
        [
            "id" => "detail_square_1",
            "label" => "Detail Page square Ad1"
        ],
        [
            "id" => "detail_rectangle",
            "label" => "Detail Page rectangle Ad"
        ],
        [
            "id" => "detail_square_2",
            "label" => "Detail Page square Ad2"
        ]
    ];

    return [
        "status" => true,
        "data" => $placements
    ];
}



//Admap API
function newsroom_advertise_api(WP_REST_Request $request)
{
    $full_name = sanitize_text_field($request->get_param('full_name'));
    $email     = sanitize_email($request->get_param('email'));
    $phone     = sanitize_text_field($request->get_param('phone'));
    $company   = sanitize_text_field($request->get_param('company'));
    $placement = sanitize_text_field($request->get_param('placement'));

    if (!$full_name || !$email || !$phone || !$placement) {
        return [
            'status' => false,
            'message' => 'Required fields are missing'
        ];
    }

    // ✅ Allowed placements
    $allowed = [
        'bottom_bar_sticky',
        'home_popup',
        'detail_square_1',
        'detail_rectangle',
        'detail_square_2'
    ];

    if (!in_array($placement, $allowed)) {
        return [
            'status' => false,
            'message' => 'Invalid ad placement selected'
        ];
    }

    // ✅ File upload
    $file_url = '';

    if (!empty($_FILES['ad_file'])) {

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/media.php';
        require_once ABSPATH . 'wp-admin/includes/image.php';

        $upload = media_handle_upload('ad_file', 0);

        if (is_wp_error($upload)) {
            return [
                'status' => false,
                'message' => 'File upload failed'
            ];
        }

        $file_url = wp_get_attachment_url($upload);
    }

    // ✅ Create custom post
    $post_id = wp_insert_post([
        'post_title' => $full_name . ' - Ad Request',
        'post_type' => 'advertise_requests',
        'post_status' => 'publish'
    ]);

    if (!$post_id) {
        return [
            'status' => false,
            'message' => 'Could not save request'
        ];
    }

    // ✅ Save meta
    update_post_meta($post_id, 'full_name', $full_name);
    update_post_meta($post_id, 'email', $email);
    update_post_meta($post_id, 'phone', $phone);
    update_post_meta($post_id, 'company', $company);
    update_post_meta($post_id, 'placement', $placement);
    update_post_meta($post_id, 'file', $file_url);

    return [
        'status' => true,
        'message' => 'Advertisement request submitted successfully',
        'data' => [
            'id' => $post_id,
            'full_name' => $full_name,
            'email' => $email,
            'phone' => $phone,
            'company' => $company,
            'placement' => $placement,
            'file_url' => $file_url
        ]
    ];
}



//Flexible Content Layout get page data
function myapi_get_flexible_layout_label($field_name, $layout_name)
{

    $field = get_field_object($field_name, 'option');
    if (empty($field['layouts'])) {
        return null;
    }

    foreach ($field['layouts'] as $layout) {
        if ($layout['name'] === $layout_name) {
            return $layout['label'];
        }
    }

    return null;
}

/**
 * Callback: Get Home Data
 */
function myapi_get_home_data(WP_REST_Request $request)
{

    // 🔐 Check JWT once for home API
    $is_logged_in = false;
    $user_payload = null;

    $auth_header = $request->get_header('Authorization');
    if (empty($auth_header)) {
        $auth_header = $request->get_header('authorization');
    }

    if (!empty($auth_header) && function_exists('newsroomapi_verify_jwt')) {
        $payload = newsroomapi_verify_jwt($auth_header);

        if (is_array($payload) && !empty($payload['sub'])) {
            $is_logged_in = true;
            $user_payload = $payload; // if needed later
        }
    }


    // 1. Fetch Advertisement Options (Global)
    // Check if get_field exists to avoid fatal error
    if (!function_exists('get_field')) {
        return new WP_REST_Response([
            'success' => false,
            'message' => 'ACF not active'
        ], 500);
    }


    // Advertisement Fields
    $show_advertise               = get_field('breaking_advertisement', 'option');
    $selected_advertise           = get_field('advert_select', 'option');
    $breaking_abovebelow_section  = get_field('breaking_abovebelow_section', 'option');

    // Handle boolean check for show_advertise
    $show_advertise = filter_var($show_advertise, FILTER_VALIDATE_BOOLEAN);

    // 2. Fetch Sections via Flexible Content
    $sections_data = [];
    $flexible_sections = get_field('advert_section', 'option');

    if (is_array($flexible_sections)) {
        foreach ($flexible_sections as $section) {
            $layout = isset($section['acf_fc_layout']) ? $section['acf_fc_layout'] : '';

            if ($layout === 'main_advert_top') {
                $title = myapi_get_flexible_layout_label('advert_section', $layout) ?: 'Main Advert Top';

                // Get Section Specific Advertisement Settings
                $section_show_ad = isset($section['main_top_advertise']) ? $section['main_top_advertise'] : false;
                $section_ad_select = isset($section['main_top_advert_select']) ? $section['main_top_advert_select'] : null;

                // Normalize boolean
                $section_show_ad = filter_var($section_show_ad, FILTER_VALIDATE_BOOLEAN);

                $ad_data = null;

                if ($section_show_ad && !empty($section_ad_select) && function_exists('adrotate_mobile_api_get_ads')) {

                    $ad_request = new WP_REST_Request('GET');
                    $ad_request->set_param('group_id', (int) $section_ad_select);

                    $ad_response = adrotate_mobile_api_get_ads($ad_request);

                    if (!is_wp_error($ad_response)) {
                        if ($ad_response instanceof WP_REST_Response) {
                            $ad_data = $ad_response->get_data();
                        } else {
                            $ad_data = $ad_response;
                        }
                    }
                }




                $sections_data[] = [
                    'type'           => 'Main Top Advertise',
                    'title'          => $title,
                    'is_advertise'   => $section_show_ad,
                    'advert_select'  => $section_show_ad ? $section_ad_select : null,
                    'advert_code'    => $ad_data,

                ];
            }


            if ($layout === 'breaking_news') {
                $title = myapi_get_flexible_layout_label('advert_section', $layout) ?: 'Breaking News';

                // Get Section Specific Advertisement Settings
                $section_show_ad = isset($section['breaking_advertisement']) ? $section['breaking_advertisement'] : false;
                $section_ad_select = isset($section['advert_select']) ? $section['advert_select'] : null;
                $breaking_abovebelow_section = isset($section['breaking_abovebelow_section']) ? $section['breaking_abovebelow_section'] : false;
                $breaking_abovebelow_section = filter_var($breaking_abovebelow_section, FILTER_VALIDATE_BOOLEAN);

                // Normalize boolean
                $section_show_ad = filter_var($section_show_ad, FILTER_VALIDATE_BOOLEAN);

                $ad_data = null;

                if ($section_show_ad && !empty($section_ad_select) && function_exists('adrotate_mobile_api_get_ads')) {

                    $ad_request = new WP_REST_Request('GET');
                    $ad_request->set_param('group_id', (int) $section_ad_select);

                    $ad_response = adrotate_mobile_api_get_ads($ad_request);

                    if (!is_wp_error($ad_response)) {
                        if ($ad_response instanceof WP_REST_Response) {
                            $ad_data = $ad_response->get_data();
                        } else {
                            $ad_data = $ad_response;
                        }
                    }
                }


                // Fetch Latest Posts via myapi_get_posts_by_category
                $posts_data = [];

                if (function_exists('myapi_get_posts_by_category')) {
                    // Handle optional limit for breaking news
                    $limit = $request->get_param('breaking_news_limit');
                    $original_ppp = $request->get_param('posts_per_page');

                    if (!empty($limit)) {
                        $request->set_param('posts_per_page', absint($limit));
                    }

                    // Use original request to keep context
                    $response = myapi_get_posts_by_category($request);

                    // Restore original ppp if changed
                    if (!empty($limit)) {
                        $request->set_param('posts_per_page', $original_ppp);
                    }

                    if ($response instanceof WP_REST_Response) {
                        $response_data_inner = $response->get_data();
                        if (isset($response_data_inner['data']) && is_array($response_data_inner['data'])) {
                            $posts_data = $response_data_inner['data'];
                        }
                    }
                }

                $sections_data[] = [
                    'type'           => 'breaking_news',
                    'title'          => $title,
                    'is_advertise'   => $section_show_ad,
                    'advert_select'  => $section_show_ad ? $section_ad_select : null,
                    'advert_code'    => $ad_data,
                    'data'           => $posts_data,
                    'breaking_abovebelow_section' => $breaking_abovebelow_section,

                ];
            }

            if ($layout === 'recommended_news' && $is_logged_in) {

                $title = myapi_get_flexible_layout_label('advert_section', $layout) ?: 'Recommended News';

                // Section ad settings
                $section_show_ad   = isset($section['recmmended_advertisement']) ? $section['recmmended_advertisement'] : false;
                $section_ad_select = isset($section['recommended_advert_select']) ? $section['recommended_advert_select'] : null;

                $section_show_ad = filter_var($section_show_ad, FILTER_VALIDATE_BOOLEAN);
                $recommended_abovebelow_section = isset($section['recommended_abovebelow_section']) ? $section['recommended_abovebelow_section'] : false;
                $recommended_abovebelow_section = filter_var($recommended_abovebelow_section, FILTER_VALIDATE_BOOLEAN);
                $ad_data = null;

                if ($section_show_ad && !empty($section_ad_select) && function_exists('adrotate_mobile_api_get_ads')) {

                    $ad_request = new WP_REST_Request('GET');
                    $ad_request->set_param('group_id', (int) $section_ad_select);

                    $ad_response = adrotate_mobile_api_get_ads($ad_request);

                    if (!is_wp_error($ad_response)) {
                        if ($ad_response instanceof WP_REST_Response) {
                            $ad_data = $ad_response->get_data();
                        } else {
                            $ad_data = $ad_response;
                        }
                    }
                }


                // ✅ CALL RECOMMENDED API
                $recommended_response = null;

                if ($is_logged_in && function_exists('myapi_get_recommended_posts')) {

                    $rec_request = new WP_REST_Request('GET');

                    $rec_request->set_header('authorization', $auth_header);

                    $rec_request->set_param('posts_per_category', 5);

                    $response = myapi_get_recommended_posts($rec_request);

                    if (!is_wp_error($response)) {
                        // ✅ get full response, not only ['data']
                        $recommended_response = $response->get_data();
                    }
                }

                $sections_data[] = [
                    'type'          => 'recommended_news',
                    'title'         => $title,
                    'is_advertise'  => $section_show_ad,
                    'advert_select' => $section_show_ad ? $section_ad_select : null,
                    'advert_code'   => $ad_data,

                    // ✅ exact same structure as /recommended-posts
                    'data'          => $recommended_response,
                    'recommended_abovebelow_section' => $recommended_abovebelow_section,

                ];
            }
            if ($layout === 'top_videos') {

                $title = myapi_get_flexible_layout_label('advert_section', $layout) ?: 'Top Videos';

                // Section ad settings
                $section_show_ad   = isset($section['top_videos_advert']) ? $section['top_videos_advert'] : false;
                $section_ad_select = isset($section['top_videos_select']) ? $section['top_videos_select'] : null;

                $section_show_ad = filter_var($section_show_ad, FILTER_VALIDATE_BOOLEAN);

                // Above / below control
                $top_videos_abovebelow_section = isset($section['top_videos_abovebelow_section'])
                    ? $section['top_videos_abovebelow_section']
                    : false;

                $top_videos_abovebelow_section = filter_var($top_videos_abovebelow_section, FILTER_VALIDATE_BOOLEAN);

                $ad_data = null;

                if ($section_show_ad && !empty($section_ad_select) && function_exists('adrotate_mobile_api_get_ads')) {

                    $ad_request = new WP_REST_Request('GET');
                    $ad_request->set_param('group_id', (int) $section_ad_select);

                    $ad_response = adrotate_mobile_api_get_ads($ad_request);

                    if (!is_wp_error($ad_response)) {
                        if ($ad_response instanceof WP_REST_Response) {
                            $ad_data = $ad_response->get_data();
                        } else {
                            $ad_data = $ad_response;
                        }
                    }
                }

                // ✅ CALL TOP VIDEOS API
                $videos_response = null;

                if (function_exists('myapi_get_latest_videos')) {

                    $video_request = new WP_REST_Request('GET');

                    // Forward JWT (if your videos API needs it)
                    $auth_header = $request->get_header('Authorization');
                    if (empty($auth_header)) {
                        $auth_header = $request->get_header('authorization');
                    }

                    if (!empty($auth_header)) {
                        $video_request->set_header('Authorization', $auth_header);
                    }

                    $response = myapi_get_latest_videos($video_request);

                    if (!is_wp_error($response)) {
                        // ✅ exact same response as /latest-videos
                        $videos_response = $response->get_data();
                    }
                }

                $sections_data[] = [
                    'type'         => 'top_videos',
                    'title'        => $title,
                    'is_advertise' => $section_show_ad,
                    'advert_select' => $section_show_ad ? $section_ad_select : null,
                    'advert_code'  => $ad_data,
                    'data' => $videos_response,
                    'top_videos_abovebelow_section' => $top_videos_abovebelow_section,
                ];
            }

            if ($layout === 'continue_reading' && $is_logged_in) {

                $title = myapi_get_flexible_layout_label('advert_section', $layout) ?: 'Continue Reading';

                // Section ad settings
                $section_show_ad   = isset($section['continue_reading_advert']) ? $section['continue_reading_advert'] : false;
                $section_ad_select = isset($section['continue_reading_select']) ? $section['continue_reading_select'] : null;

                $section_show_ad = filter_var($section_show_ad, FILTER_VALIDATE_BOOLEAN);

                // Above / below control
                $continue_reading_abovebelow_section = isset($section['continue_reading_abovebelow_section'])
                    ? $section['continue_reading_abovebelow_section']
                    : false;

                $continue_reading_abovebelow_section = filter_var($continue_reading_abovebelow_section, FILTER_VALIDATE_BOOLEAN);

                $ad_data = null;

                if ($section_show_ad && !empty($section_ad_select) && function_exists('adrotate_mobile_api_get_ads')) {

                    $ad_request = new WP_REST_Request('GET');
                    $ad_request->set_param('group_id', (int) $section_ad_select);

                    $ad_response = adrotate_mobile_api_get_ads($ad_request);

                    if (!is_wp_error($ad_response)) {
                        if ($ad_response instanceof WP_REST_Response) {
                            $ad_data = $ad_response->get_data();
                        } else {
                            $ad_data = $ad_response;
                        }
                    }
                }

                // ✅ CALL CONTINUE READING API
                $continue_response = null;

                if ($is_logged_in && function_exists('myapi_get_continue_reading')) {

                    $continue_request = new WP_REST_Request('GET');

                    $continue_request->set_header('authorization', $auth_header);


                    if (!empty($auth_header)) {
                        $continue_request->set_header('Authorization', $auth_header);
                    }

                    $response = myapi_get_continue_reading($continue_request);

                    if (!is_wp_error($response)) {
                        // ✅ exact same structure as /continue-reading
                        $continue_response = $response->get_data();
                    }
                }

                $sections_data[] = [
                    'type'         => 'continue_reading',
                    'title'        => $title,
                    'is_advertise' => $section_show_ad,
                    'advert_select' => $section_show_ad ? $section_ad_select : null,
                    'advert_code'  => $ad_data,

                    // control flag
                    'continue_reading_abovebelow_section' => $continue_reading_abovebelow_section,

                    // ✅ exact API response
                    'data' => $continue_response,
                ];
            }

            if ($layout === 'explore_more') {

                // ✅ Dynamic title from ACF layout label
                $title = myapi_get_flexible_layout_label('advert_section', $layout) ?: 'Explore More';

                // Section ad settings
                $section_show_ad   = isset($section['explore_more_advert']) ? $section['explore_more_advert'] : false;
                $section_ad_select = isset($section['explore_more_select']) ? $section['explore_more_select'] : null;

                $section_show_ad = filter_var($section_show_ad, FILTER_VALIDATE_BOOLEAN);

                // Above / below control
                $explore_more_abovebelow_section = isset($section['explore_more_abovebelow_section'])
                    ? $section['explore_more_abovebelow_section']
                    : false;

                $explore_more_abovebelow_section = filter_var($explore_more_abovebelow_section, FILTER_VALIDATE_BOOLEAN);

                $ad_data = null;

                if ($section_show_ad && !empty($section_ad_select) && function_exists('adrotate_mobile_api_get_ads')) {

                    $ad_request = new WP_REST_Request('GET');
                    $ad_request->set_param('group_id', (int) $section_ad_select);

                    $ad_response = adrotate_mobile_api_get_ads($ad_request);

                    if (!is_wp_error($ad_response)) {
                        if ($ad_response instanceof WP_REST_Response) {
                            $ad_data = $ad_response->get_data();
                        } else {
                            $ad_data = $ad_response;
                        }
                    }
                }

                // ✅ CALL EXPLORE MORE API
                $explore_response = null;

                if (function_exists('myapi_get_categories')) {

                    $explore_request = new WP_REST_Request('GET');

                    // (no JWT needed for categories, but safe if later required)
                    $auth_header = $request->get_header('Authorization');
                    if (empty($auth_header)) {
                        $auth_header = $request->get_header('authorization');
                    }

                    if (!empty($auth_header)) {
                        $explore_request->set_header('Authorization', $auth_header);
                    }

                    $response = myapi_get_categories($explore_request);

                    if (!is_wp_error($response)) {
                        // If function returns array instead of WP_REST_Response
                        if ($response instanceof WP_REST_Response) {
                            $explore_response = $response->get_data();
                        } else {
                            $explore_response = $response;
                        }
                    }
                }

                $sections_data[] = [
                    'type'         => 'explore_more',
                    'title'        => $title,
                    'is_advertise' => $section_show_ad,
                    'advert_select' => $section_show_ad ? $section_ad_select : null,
                    'advert_code'  => $ad_data,

                    // control flag
                    'explore_more_abovebelow_section' => $explore_more_abovebelow_section,

                    // ✅ exact API response
                    'data' => $explore_response,
                ];
            }

            if ($layout === 'footer_sticky_advert') {

                // ✅ Dynamic title from ACF layout label
                $title = myapi_get_flexible_layout_label('advert_section', $layout) ?: 'Explore More';

                // Section ad settings
                $section_show_ad   = isset($section['footer_botoom_advertise']) ? $section['footer_botoom_advertise'] : false;
                $section_ad_select = isset($section['footer_botom_advert_select']) ? $section['footer_botom_advert_select'] : null;

                $section_show_ad = filter_var($section_show_ad, FILTER_VALIDATE_BOOLEAN);

                $ad_data = null;

                if ($section_show_ad && !empty($section_ad_select) && function_exists('adrotate_mobile_api_get_ads')) {

                    $ad_request = new WP_REST_Request('GET');
                    $ad_request->set_param('group_id', (int) $section_ad_select);

                    $ad_response = adrotate_mobile_api_get_ads($ad_request);

                    if (!is_wp_error($ad_response)) {
                        if ($ad_response instanceof WP_REST_Response) {
                            $ad_data = $ad_response->get_data();
                        } else {
                            $ad_data = $ad_response;
                        }
                    }
                }

                $sections_data[] = [
                    'type'         => 'footer_stikcy_ad',
                    'title'        => $title,
                    'is_advertise' => $section_show_ad,
                    'advert_select' => $section_show_ad ? $section_ad_select : null,
                    'advert_code'  => $ad_data,
                ];
            }
        }
    }

    // 3. Construct Response    
    $response_data = [
        'sections'            => $sections_data,
    ];

    return new WP_REST_Response([
        'success' => true,
        'data'    => $response_data
    ], 200);
}

//Post detail PAGE API
function myapi_get_single_post_detail(WP_REST_Request $request)
{
    $post_id = intval($request->get_param('post_id'));

    if (!$post_id || get_post_status($post_id) !== 'publish') {
        return array(
            'status' => false,
            'message' => 'Invalid post ID'
        );
    }


    // 🔐 Check JWT once for home API
    $is_logged_in = false;
    $user_payload = null;

    $auth_header = $request->get_header('Authorization');
    if (empty($auth_header)) {
        $auth_header = $request->get_header('authorization');
    }

    if (!empty($auth_header) && function_exists('newsroomapi_verify_jwt')) {
        $payload = newsroomapi_verify_jwt($auth_header);

        if (is_array($payload) && !empty($payload['sub'])) {
            $is_logged_in = true;
            $user_payload = $payload; // if needed later
        }
    }


    /* ------------------------
   1️⃣ TOP AD (ACF OPTION)
    -------------------------*/
    $top_ad_group_id = get_field('post_detail_top_advert', 'option');
    $top_ad = null;
    if (!empty($top_ad_group_id) && function_exists('adrotate_mobile_api_get_ads')) {
        $top_ad_request = new WP_REST_Request('GET');
        $top_ad_request->set_param('group_id', (int) $top_ad_group_id);

        $top_ad_response = adrotate_mobile_api_get_ads($top_ad_request);

        if (!is_wp_error($top_ad_response)) {
            $top_ad = $top_ad_response instanceof WP_REST_Response
                ? $top_ad_response->get_data()
                : $top_ad_response;
        }
    }

    /* ------------------------
       2️⃣ SINGLE POST DATA (Consolidated call)
    -------------------------*/
    $single_post = null;
    $related_posts = [];

    if (function_exists('myapi_get_single_post')) {
        $internal_request = new WP_REST_Request('GET');
        $internal_request->set_param('post_id', $post_id);

        $post_response = myapi_get_single_post($internal_request);

        if ($post_response instanceof WP_REST_Response) {
            $post_data_payload = $post_response->get_data();
            $single_post = isset($post_data_payload['post']) ? $post_data_payload['post'] : null;
            $related_posts = isset($post_data_payload['related_posts']) ? $post_data_payload['related_posts'] : [];
        } else if (is_array($post_response)) {
            $single_post = isset($post_response['post']) ? $post_response['post'] : null;
            $related_posts = isset($post_response['related_posts']) ? $post_response['related_posts'] : [];
        }
    }

    // Fallback if needed (though myapi_get_single_post should exist)
    if (!$single_post) {
        $post = get_post($post_id);
        $single_post = array(
            'id' => $post->ID,
            'title' => get_the_title($post->ID),
            'content' => apply_filters('the_content', $post->post_content),
            'excerpt' => get_the_excerpt($post->ID),
            'date' => get_the_date('M j, Y', $post->ID),
            'author' => get_the_author_meta('display_name', $post->post_author),
            'featured_image' => get_the_post_thumbnail_url($post->ID, 'full'),
            'categories' => wp_get_post_categories($post_id, array('fields' => 'names')),
            'tags' => wp_get_post_tags($post_id, array('fields' => 'names'))
        );
    }

    /* ------------------------
   3️⃣ BOTTOM AD (ACF OPTION)
-------------------------*/
    $bottom_ad_group_id = get_field('post_detail_bottom_advert', 'option');
    $bottom_ad = null;
    if (!empty($bottom_ad_group_id) && function_exists('adrotate_mobile_api_get_ads')) {
        $bottom_ad_request = new WP_REST_Request('GET');
        $bottom_ad_request->set_param('group_id', (int) $bottom_ad_group_id);

        $bottom_ad_response = adrotate_mobile_api_get_ads($bottom_ad_request);

        if (!is_wp_error($bottom_ad_response)) {
            $bottom_ad = $bottom_ad_response instanceof WP_REST_Response
                ? $bottom_ad_response->get_data()
                : $bottom_ad_response;
        }
    }


    // 2. Fetch Sections via Flexible Content
    $sections_data = [];
    $flexible_sections = get_field('post_detail_section', 'option');

    if (is_array($flexible_sections)) {
        foreach ($flexible_sections as $section) {
            $layout = isset($section['acf_fc_layout']) ? $section['acf_fc_layout'] : '';
            /* =====================================================
                RECOMMENDED STORIES SECTION
            =====================================================*/
            if ($is_logged_in && $layout === 'recommended_stories') {

                $title = myapi_get_flexible_layout_label('post_detail_section', $layout) ?: 'Recommended Stories';
                // Section ad settings
                $section_show_ad   = isset($section['recmmended_stories_advertisement']) ? $section['recmmended_stories_advertisement'] : false;
                $section_ad_select = isset($section['recommended_stories_advert_select']) ? $section['recommended_stories_advert_select'] : null;

                $section_show_ad = filter_var($section_show_ad, FILTER_VALIDATE_BOOLEAN);
                $ad_data = null;

                if ($section_show_ad && !empty($section_ad_select) && function_exists('adrotate_mobile_api_get_ads')) {

                    $ad_request = new WP_REST_Request('GET');
                    $ad_request->set_param('group_id', (int) $section_ad_select);

                    $ad_response = adrotate_mobile_api_get_ads($ad_request);

                    if (!is_wp_error($ad_response)) {
                        if ($ad_response instanceof WP_REST_Response) {
                            $ad_data = $ad_response->get_data();
                        } else {
                            $ad_data = $ad_response;
                        }
                    }
                }


                // ✅ CALL RECOMMENDED API
                $recommended_response = null;


                if ($is_logged_in && function_exists('myapi_get_recommended_posts')) {

                    $rec_request = new WP_REST_Request('GET');

                    $rec_request->set_header('authorization', $auth_header);

                    $rec_request->set_param('posts_per_category', 5);

                    $response = myapi_get_recommended_posts($rec_request);

                    if (!is_wp_error($response)) {
                        // ✅ get full response, not only ['data']
                        $recommended_response = $response->get_data();
                    }
                }

                $sections_data[] = [
                    'type'          => 'recommended_stories',
                    'title'         => $title,
                    'is_advertise'  => $section_show_ad,
                    'advert_select' => $section_show_ad ? $section_ad_select : null,
                    'advert_code'   => $ad_data,
                    'data'          => $recommended_response,
                ];
            }

            if ($layout === 'explore_more') {

                // ✅ Dynamic title from ACF layout label
                $title = myapi_get_flexible_layout_label('post_detail_section', $layout) ?: 'Explore More';

                // Section ad settings
                $section_show_ad   = isset($section['explore_more_cat_advertisement']) ? $section['explore_more_cat_advertisement'] : false;
                $section_ad_select = isset($section['explore_more_advertisement_select']) ? $section['explore_more_advertisement_select'] : null;

                $section_show_ad = filter_var($section_show_ad, FILTER_VALIDATE_BOOLEAN);

                $ad_data = null;

                if ($section_show_ad && !empty($section_ad_select) && function_exists('adrotate_mobile_api_get_ads')) {

                    $ad_request = new WP_REST_Request('GET');
                    $ad_request->set_param('group_id', (int) $section_ad_select);

                    $ad_response = adrotate_mobile_api_get_ads($ad_request);

                    if (!is_wp_error($ad_response)) {
                        if ($ad_response instanceof WP_REST_Response) {
                            $ad_data = $ad_response->get_data();
                        } else {
                            $ad_data = $ad_response;
                        }
                    }
                }

                // ✅ CALL EXPLORE MORE API
                $explore_response = null;

                if (function_exists('myapi_get_categories')) {

                    $explore_request = new WP_REST_Request('GET');

                    // (no JWT needed for categories, but safe if later required)
                    $auth_header = $request->get_header('Authorization');
                    if (empty($auth_header)) {
                        $auth_header = $request->get_header('authorization');
                    }

                    if (!empty($auth_header)) {
                        $explore_request->set_header('Authorization', $auth_header);
                    }

                    $response = myapi_get_categories($explore_request);

                    if (!is_wp_error($response)) {
                        // If function returns array instead of WP_REST_Response
                        if ($response instanceof WP_REST_Response) {
                            $explore_response = $response->get_data();
                        } else {
                            $explore_response = $response;
                        }
                    }
                }

                $sections_data[] = [
                    'type'         => 'explore_more',
                    'title'        => $title,
                    'is_advertise' => $section_show_ad,
                    'advert_select' => $section_show_ad ? $section_ad_select : null,
                    'advert_code'  => $ad_data,
                    // ✅ exact API response
                    'data' => $explore_response,
                ];
            }
        }
    }


    // 3. Construct Response    
    $response_data = [
        'sections'            => $sections_data,
    ];

    return new WP_REST_Response([
        'success'       => true,
        'top_ad'        => $top_ad,
        'post'          => $single_post,
        'related_posts' => $related_posts, // ✅ Included from consolidated call
        'data'          => $response_data,
        'bottom_ad'     => $bottom_ad,
    ], 200);
}
?>