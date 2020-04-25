<?php
/*
Plugin Name: Multisite Multidomain Single Sign On
Description: Automatically sign the user in to separate-domain sites of the same multisite installation, when switching sites using the My Sites links in the admin menu. Note that the user already has to be logged into a site in the network, this plugin just cuts down on having to log in again due to cookie isolation between domains.
Version: 1.0
Author: emfluence
Author URI: https://emfluence.com
*/

/**
 * Change the links in the admin menu bar
 * @see WP_Admin_Bar
 * @see wp_admin_bar_my_sites_menu()
 */
function msso_change_site_switcher_links() {
  global $wp_admin_bar;
  $nodes = $wp_admin_bar->get_nodes();
  $current_site_id = get_current_blog_id();
  $current_site = get_site($current_site_id);
  foreach($nodes as $id=>$node) {
    if(empty($node->href)) continue;
    $is_site_node = (0 === stripos($id, 'blog'));
    $is_network_admin_node = (0 === stripos($id, 'network-admin'));
    if(!($is_site_node || $is_network_admin_node)) continue;
    if(in_array($current_site->domain, explode('/', $node->href), true)) continue;
    $node->href = add_query_arg(['msso-get-auth-from' => $current_site_id], $node->href);
    $wp_admin_bar->add_node($node);
  }
}
add_action( 'wp_before_admin_bar_render', 'msso_change_site_switcher_links' );

/*
 * Initiate the workflow, on a target site that the user wants to log into.
 */
function msso_receive_sso_request() {
  if(empty($_GET['msso-get-auth-from'])) return;
  if(is_user_logged_in()) {
    wp_redirect(remove_query_arg('msso-get-auth-from'));
    exit();
  }
  $coming_from = intval($_GET['msso-get-auth-from']);
  $sso_site = get_site($coming_from);
  if(empty($sso_site)) {
    wp_die('Single Sign On is attempting to use an invalid site on this multisite.');
  }
  $return_url = get_site_url() . remove_query_arg('msso-get-auth-from');
  $next_url = add_query_arg(['msso-auth-return-to' => $return_url], get_site_url($coming_from));
  wp_redirect($next_url);
  exit();
}
add_action('init', 'msso_receive_sso_request');

/**
 * Used on the authorizing site
 */
function msso_authorize_request() {
  if(empty($_GET['msso-auth-return-to'])) return;
  if(!is_user_logged_in()) {
    wp_die('Single Sign On requires that you be logged in. Please <a href="' . esc_url(wp_login_url()) . '">log in</a>, then try again.');
  }
  $return_url = esc_url_raw($_GET['msso-auth-return-to']);
  $current_user = wp_get_current_user();
  $expires = strtotime('+2 minutes');
  $hash = md5(intval($current_user->ID) . '||' . intval($expires));

  $next_url = add_query_arg([
    'msso-auth' => $hash,
    'msso-user-id' => $current_user->ID,
    'msso-expires' => $expires
  ], $return_url);
  wp_redirect($next_url);
  exit();
}
add_action('init', 'msso_authorize_request');

/*
 * Final step, used on the target site.
 */
function msso_receive_auth() {
  $keys = ['msso-auth', 'msso-user-id', 'msso-expires'];
  foreach($keys as $key) {
    if(empty($_GET[$key])) return;
  }
  if(is_user_logged_in()) return;

  $user_id = intval($_GET['msso-user-id']); // phpcs:ignore:WordPress.Security.ValidatedSanitizedInput.InputNotValidated
  $expires = intval($_GET['msso-expires']); // phpcs:ignore:WordPress.Security.ValidatedSanitizedInput.InputNotValidated
  $received_hash = $_GET['msso-auth']; // phpcs:ignore:WordPress.Security.ValidatedSanitizedInput.InputNotValidated

  if($expires < time()) {
    wp_die('Your Single Sing On link has expired. Please return to the dashboard and try again.');
  }
  if(md5($user_id . '||' . $expires) !== $received_hash) {
    wp_die('Single Sign On has found an error in the URL that you are trying to use.');
  }
  if(!user_can($user_id, 'read')) {
    wp_die('Single Sign On is trying to log you in, but your user account is not authorized for this site. Please contact a network admin and ask them to add you to this site.');
  }

  wp_set_auth_cookie($user_id, true);

  // Just so that we don't leave the user on a URL with a bunch of our parameters.
  $final_destination = remove_query_arg($keys);
  wp_redirect($final_destination);
  exit();
}
add_action('init', 'msso_receive_auth');
