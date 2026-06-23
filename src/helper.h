// helper.h — shared declarations for the privileged fail2ban-client helper.
//
// Fail2ban GUI runs unprivileged, but fail2ban-client needs root to reach
// /var/run/fail2ban/fail2ban.sock. Rather than wrap every command in pkexec
// (one password prompt each), the GUI spawns ONE long-lived helper through
// pkexec at first use. The helper runs as root, reads framed requests on its
// stdin, runs fail2ban-client (no shell — argv is exec'd directly), and writes
// the captured output back on stdout. One authorisation covers the session.
//
// Author: Jean-Francois Lachance-Caumartin
#pragma once
#include <string>
#include <vector>

// Run the helper event loop (called when the binary is launched with --helper,
// i.e. re-exec'd as root by pkexec). Never returns until stdin closes.
int helper_main();

// Whitelisted first tokens the helper is willing to pass to fail2ban-client.
// Anything else is rejected, so a compromised GUI can't run arbitrary commands.
bool helper_arg_allowed(const std::string &verb);
