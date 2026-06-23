// Fail2ban GUI — a GTK4 front-end for fail2ban.
//
// fail2ban is powerful but its command line is easy to get lost in. This window
// surfaces the everyday operations as buttons and lists:
//
//   * see every jail at a glance with its banned / failed counters,
//   * drill into a jail: watched log files, banned IP list, ban/unban, and the
//     bantime / findtime / maxretry knobs,
//   * a combined "Banned IPs" view across all jails with one-click unban,
//   * start / stop / reload individual jails and reload / restart the server,
//   * an activity log of everything the GUI did and how fail2ban answered.
//
// fail2ban-client needs root to reach /var/run/fail2ban/fail2ban.sock, so the
// GUI itself stays unprivileged and talks to a small root helper (see
// helper.cpp) that it launches ONCE through pkexec — a single authorisation
// for the whole session. The same binary is the helper when run with --helper.
//
// GTK4 / C++17, Tokyo Night theme — visual sibling of Warden.
//
// Author: Jean-Francois Lachance-Caumartin
// Repository: https://github.com/effjy/fail2ban-gui/

#include <gtk/gtk.h>
#include <glib-unix.h>
#ifdef GDK_WINDOWING_X11
#include <gdk/x11/gdkx.h>   // gdk_x11_get_server_time / set_user_time (raise-to-front)
#endif

#include <unistd.h>
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include "helper.h"
#include "tray.h"

#define F2B_VERSION "1.0.2"

// ---------------------------------------------------------------------------
// Parsed status of a single jail (from `fail2ban-client status <jail>`)
// ---------------------------------------------------------------------------
struct JailStatus {
    int cur_failed = 0, tot_failed = 0, cur_banned = 0, tot_banned = 0;
    std::vector<std::string> files;
    std::vector<std::string> banned;   // currently banned IPs
};

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------
struct App {
    GtkApplication *app   = nullptr;
    GtkWidget *window     = nullptr;
    GtkWidget *status_lbl = nullptr;   // server up/down / version / jail count
    GtkWidget *authorize_btn = nullptr;

    GtkWidget *log_view   = nullptr;
    GtkTextMark *log_end  = nullptr;

    // Jails page
    GtkWidget *jails_box  = nullptr;    // left list of jails
    GtkWidget *detail_title = nullptr;
    GtkWidget *st_curfail = nullptr, *st_totfail = nullptr;
    GtkWidget *st_curban  = nullptr, *st_totban  = nullptr;
    GtkWidget *files_lbl  = nullptr;
    GtkWidget *ent_bantime = nullptr, *ent_findtime = nullptr, *ent_maxretry = nullptr;
    GtkWidget *banned_box = nullptr;    // banned IPs of selected jail
    GtkWidget *ent_banip  = nullptr;
    GtkWidget *detail_actions = nullptr; // box holding per-jail buttons (sensitivity)

    // Banned-IPs page
    GtkWidget *allbanned_box = nullptr;
    GtkWidget *ent_gban_ip = nullptr;
    GtkWidget *gban_jail   = nullptr;    // GtkDropDown
    GtkStringList *gban_model = nullptr;

    // Privileged helper co-process
    int   helper_w = -1, helper_r = -1;
    pid_t helper_pid = -1;
    bool  auth_ok = false;

    std::vector<std::string>          jails;
    std::map<std::string, JailStatus> cache;
    std::string selected_jail;
};

static void refresh_all(App *app);
static void update_detail(App *app);

// ---------------------------------------------------------------------------
// Activity log
// ---------------------------------------------------------------------------
static void log_append(App *app, const std::string &line) {
    if (!app->log_view) return;
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->log_view));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);
    char t[32]; time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm);
    strftime(t, sizeof(t), "%H:%M:%S  ", &tm);
    std::string full = std::string(t) + line + "\n";
    gtk_text_buffer_insert(buf, &end, full.c_str(), -1);
    if (app->log_end)
        gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(app->log_view),
                                     app->log_end, 0.0, TRUE, 0.0, 1.0);
}

static void set_status(App *app, const std::string &text, const char *css_class) {
    gtk_label_set_text(GTK_LABEL(app->status_lbl), text.c_str());
    gtk_widget_remove_css_class(app->status_lbl, "ok");
    gtk_widget_remove_css_class(app->status_lbl, "bad");
    gtk_widget_add_css_class(app->status_lbl, css_class);
}

// ---------------------------------------------------------------------------
// Privileged-helper client
// ---------------------------------------------------------------------------
struct F2BResult { int rc = -1; std::string out; bool ok = false; };

static bool hp_write_all(int fd, const char *p, size_t len) {
    while (len) { ssize_t n = write(fd, p, len); if (n <= 0) return false; p += n; len -= (size_t)n; }
    return true;
}
static bool hp_read_line(int fd, std::string &out) {
    out.clear(); char c; ssize_t n;
    while ((n = read(fd, &c, 1)) == 1) { if (c == '\n') return true; out += c; }
    return false;
}
static bool hp_read_n(int fd, std::string &out, size_t len) {
    out.clear(); out.reserve(len); char buf[4096];
    while (out.size() < len) {
        size_t want = len - out.size();
        ssize_t n = read(fd, buf, want < sizeof(buf) ? want : sizeof(buf));
        if (n <= 0) return false;
        out.append(buf, (size_t)n);
    }
    return true;
}

static void helper_shutdown(App *app) {
    if (app->helper_w >= 0) { close(app->helper_w); app->helper_w = -1; }
    if (app->helper_r >= 0) { close(app->helper_r); app->helper_r = -1; }
    if (app->helper_pid > 0) { waitpid(app->helper_pid, nullptr, WNOHANG); app->helper_pid = -1; }
    app->auth_ok = false;
}

static const char *self_exe_path() {
    static char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return nullptr;
    buf[n] = 0;
    return buf;
}

// Spawn `pkexec <self> --helper`. Returns false only if we couldn't fork/exec;
// whether the user actually authorised is discovered on the first read.
static bool helper_spawn(App *app) {
    if (app->helper_w >= 0) return true;
    const char *exe = self_exe_path();
    if (!exe) return false;

    int in_pipe[2], out_pipe[2];
    if (pipe(in_pipe) != 0) return false;
    if (pipe(out_pipe) != 0) { close(in_pipe[0]); close(in_pipe[1]); return false; }

    pid_t pid = fork();
    if (pid < 0) {
        close(in_pipe[0]); close(in_pipe[1]); close(out_pipe[0]); close(out_pipe[1]);
        return false;
    }
    if (pid == 0) {
        dup2(in_pipe[0], 0);
        dup2(out_pipe[1], 1);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        execlp("pkexec", "pkexec", exe, "--helper", (char *)nullptr);
        _exit(127);
    }
    close(in_pipe[0]); close(out_pipe[1]);
    app->helper_w = in_pipe[1];
    app->helper_r = out_pipe[0];
    app->helper_pid = pid;
    return true;
}

// Run a fail2ban-client command through the helper. Blocking, but commands are
// quick and user-initiated. On the very first call this triggers pkexec's
// password prompt; if the user cancels, the helper's stdin closes and we report
// the failure so the caller can offer to retry.
static F2BResult f2b_call(App *app, const std::vector<std::string> &args) {
    F2BResult r;
    // Reject anything with an embedded newline — it would desync the frame.
    for (const auto &a : args)
        if (a.find('\n') != std::string::npos) { r.out = "invalid argument"; return r; }

    if (!helper_spawn(app)) { r.out = "could not start helper"; return r; }

    std::string frame = std::to_string(args.size()) + "\n";
    for (const auto &a : args) frame += a + "\n";
    if (!hp_write_all(app->helper_w, frame.data(), frame.size())) {
        helper_shutdown(app); r.out = "helper write failed"; return r;
    }
    std::string hdr;
    if (!hp_read_line(app->helper_r, hdr)) {
        helper_shutdown(app);
        r.out = "authorization failed or cancelled";
        return r;
    }
    int rc = 0; long len = 0;
    sscanf(hdr.c_str(), "%d %ld", &rc, &len);
    std::string body;
    if (len > 0 && !hp_read_n(app->helper_r, body, (size_t)len)) {
        helper_shutdown(app); r.out = "helper short read"; return r;
    }
    r.rc = rc; r.out = body; r.ok = true;
    app->auth_ok = true;
    return r;
}

// ---------------------------------------------------------------------------
// fail2ban-client output parsing
// ---------------------------------------------------------------------------
static std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::vector<std::string> split_ws(const std::string &s) {
    std::vector<std::string> out; std::string cur;
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == ',' || c == '\r' || c == '\n') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// If `line` contains `key`, return the trimmed text following it.
static bool value_after(const std::string &line, const char *key, std::string &out) {
    size_t p = line.find(key);
    if (p == std::string::npos) return false;
    out = trim(line.substr(p + strlen(key)));
    return true;
}

static std::vector<std::string> parse_jail_list(const std::string &status_out) {
    std::vector<std::string> jails;
    std::string val;
    size_t start = 0;
    while (start < status_out.size()) {
        size_t nl = status_out.find('\n', start);
        std::string l = status_out.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
        if (value_after(l, "Jail list:", val))
            jails = split_ws(val);
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    return jails;
}

static JailStatus parse_jail_status(const std::string &out) {
    JailStatus js;
    std::string val;
    size_t start = 0;
    while (start < out.size()) {
        size_t nl = out.find('\n', start);
        std::string l = out.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
        if      (value_after(l, "Currently failed:", val)) js.cur_failed = atoi(val.c_str());
        else if (value_after(l, "Total failed:",     val)) js.tot_failed = atoi(val.c_str());
        else if (value_after(l, "Currently banned:", val)) js.cur_banned = atoi(val.c_str());
        else if (value_after(l, "Total banned:",     val)) js.tot_banned = atoi(val.c_str());
        else if (value_after(l, "File list:",        val)) js.files  = split_ws(val);
        else if (value_after(l, "Journal matches:",  val)) { if (!val.empty()) js.files.push_back(val); }
        else if (value_after(l, "Banned IP list:",   val)) js.banned = split_ws(val);
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    return js;
}

// ---------------------------------------------------------------------------
// Small UI helpers
// ---------------------------------------------------------------------------
static void clear_listbox(GtkWidget *box) {
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(box)))
        gtk_list_box_remove(GTK_LIST_BOX(box), child);
}

static GtkWidget *make_stat(const char *caption, GtkWidget **value_out) {
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *v = gtk_label_new("–");
    gtk_widget_add_css_class(v, "statnum");
    gtk_label_set_xalign(GTK_LABEL(v), 0.0);
    GtkWidget *c = gtk_label_new(caption);
    gtk_widget_add_css_class(c, "statcap");
    gtk_label_set_xalign(GTK_LABEL(c), 0.0);
    gtk_box_append(GTK_BOX(col), v);
    gtk_box_append(GTK_BOX(col), c);
    gtk_widget_set_hexpand(col, TRUE);
    *value_out = v;
    return col;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------
// Run a command, log the outcome, and report whether it succeeded.
static bool do_action(App *app, const std::vector<std::string> &args, const std::string &human) {
    F2BResult r = f2b_call(app, args);
    if (!r.ok) {
        log_append(app, "✗ " + human + " — " + trim(r.out));
        if (!app->auth_ok)
            set_status(app, "Not authorized — click Authorize", "bad");
        return false;
    }
    std::string tail = trim(r.out);
    if (r.rc == 0)
        log_append(app, "✓ " + human + (tail.empty() ? "" : "  (" + tail + ")"));
    else
        log_append(app, "✗ " + human + " — " + (tail.empty() ? "failed" : tail));
    return r.rc == 0;
}

static bool valid_ip_token(const std::string &s) {
    if (s.empty()) return false;
    for (char c : s) if (c == ' ' || c == '\t' || c == '\n' || c == '\r') return false;
    return true;
}

struct IpJail { App *app; std::string ip; std::string jail; };

static void on_unban_clicked(GtkButton *btn, gpointer) {
    IpJail *ij = (IpJail *)g_object_get_data(G_OBJECT(btn), "ij");
    if (!ij) return;
    if (do_action(ij->app, {"set", ij->jail, "unbanip", ij->ip},
                  "unban " + ij->ip + " from " + ij->jail))
        refresh_all(ij->app);
}

static void on_jail_banip(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (app->selected_jail.empty()) return;
    std::string ip = trim(gtk_editable_get_text(GTK_EDITABLE(app->ent_banip)));
    if (!valid_ip_token(ip)) { log_append(app, "Enter an IP address to ban."); return; }
    if (do_action(app, {"set", app->selected_jail, "banip", ip},
                  "ban " + ip + " in " + app->selected_jail)) {
        gtk_editable_set_text(GTK_EDITABLE(app->ent_banip), "");
        refresh_all(app);
    }
}

static void on_jail_unban_all(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (app->selected_jail.empty()) return;
    auto it = app->cache.find(app->selected_jail);
    if (it == app->cache.end() || it->second.banned.empty()) {
        log_append(app, "No banned IPs to clear in " + app->selected_jail);
        return;
    }
    std::vector<std::string> args = {"set", app->selected_jail, "unbanip"};
    for (const auto &ip : it->second.banned) args.push_back(ip);
    if (do_action(app, args, "unban all in " + app->selected_jail))
        refresh_all(app);
}

static void on_apply_config(GtkButton *, gpointer data) {
    App *app = (App *)data;
    if (app->selected_jail.empty()) return;
    const std::string &j = app->selected_jail;
    struct { GtkWidget *e; const char *key; } fields[] = {
        { app->ent_bantime,  "bantime"  },
        { app->ent_findtime, "findtime" },
        { app->ent_maxretry, "maxretry" },
    };
    bool any = false;
    for (auto &f : fields) {
        std::string v = trim(gtk_editable_get_text(GTK_EDITABLE(f.e)));
        if (v.empty() || !valid_ip_token(v)) continue;
        if (do_action(app, {"set", j, f.key, v},
                      std::string("set ") + f.key + " = " + v + " for " + j))
            any = true;
    }
    if (any) refresh_all(app);
}

static void on_jail_start(GtkButton *, gpointer d) { App*a=(App*)d; if(!a->selected_jail.empty() && do_action(a,{"start",a->selected_jail},"start jail "+a->selected_jail)) refresh_all(a); }
static void on_jail_stop (GtkButton *, gpointer d) { App*a=(App*)d; if(!a->selected_jail.empty() && do_action(a,{"stop", a->selected_jail},"stop jail " +a->selected_jail)) refresh_all(a); }
static void on_jail_reload(GtkButton *, gpointer d){ App*a=(App*)d; if(!a->selected_jail.empty() && do_action(a,{"reload",a->selected_jail},"reload jail "+a->selected_jail)) refresh_all(a); }

static void on_server_reload(GtkButton *, gpointer d)  { App*a=(App*)d; if(do_action(a,{"reload"}, "reload server"))  refresh_all(a); }
static void on_server_restart(GtkButton *, gpointer d) { App*a=(App*)d; if(do_action(a,{"restart"},"restart server")) refresh_all(a); }
static void on_refresh_clicked(GtkButton *, gpointer d){ refresh_all((App*)d); }

static void on_global_ban(GtkButton *, gpointer data) {
    App *app = (App *)data;
    std::string ip = trim(gtk_editable_get_text(GTK_EDITABLE(app->ent_gban_ip)));
    if (!valid_ip_token(ip)) { log_append(app, "Enter an IP address to ban."); return; }
    guint idx = gtk_drop_down_get_selected(GTK_DROP_DOWN(app->gban_jail));
    if (idx == GTK_INVALID_LIST_POSITION || idx >= app->jails.size()) {
        log_append(app, "Select a jail to ban in."); return;
    }
    std::string jail = app->jails[idx];
    if (do_action(app, {"set", jail, "banip", ip}, "ban " + ip + " in " + jail)) {
        gtk_editable_set_text(GTK_EDITABLE(app->ent_gban_ip), "");
        refresh_all(app);
    }
}

static void on_authorize(GtkButton *, gpointer data) {
    App *app = (App *)data;
    log_append(app, "Requesting authorization…");
    refresh_all(app);
}

// ---------------------------------------------------------------------------
// Jail selection / detail panel
// ---------------------------------------------------------------------------
static void load_jail_config(App *app) {
    auto getv = [&](const char *key, GtkWidget *e) {
        F2BResult r = f2b_call(app, {"get", app->selected_jail, key});
        gtk_editable_set_text(GTK_EDITABLE(e), r.ok && r.rc == 0 ? trim(r.out).c_str() : "");
    };
    if (app->selected_jail.empty()) return;
    getv("bantime",  app->ent_bantime);
    getv("findtime", app->ent_findtime);
    getv("maxretry", app->ent_maxretry);
}

static void update_detail(App *app) {
    bool have = !app->selected_jail.empty();
    gtk_widget_set_sensitive(app->detail_actions, have);
    gtk_widget_set_sensitive(app->ent_banip, have);

    if (!have) {
        gtk_label_set_text(GTK_LABEL(app->detail_title), "Select a jail");
        for (GtkWidget *w : { app->st_curfail, app->st_totfail, app->st_curban, app->st_totban })
            gtk_label_set_text(GTK_LABEL(w), "–");
        gtk_label_set_text(GTK_LABEL(app->files_lbl), "");
        clear_listbox(app->banned_box);
        return;
    }

    gtk_label_set_text(GTK_LABEL(app->detail_title), app->selected_jail.c_str());
    JailStatus &js = app->cache[app->selected_jail];
    gtk_label_set_text(GTK_LABEL(app->st_curfail), std::to_string(js.cur_failed).c_str());
    gtk_label_set_text(GTK_LABEL(app->st_totfail), std::to_string(js.tot_failed).c_str());
    gtk_label_set_text(GTK_LABEL(app->st_curban),  std::to_string(js.cur_banned).c_str());
    gtk_label_set_text(GTK_LABEL(app->st_totban),  std::to_string(js.tot_banned).c_str());

    std::string files;
    for (size_t i = 0; i < js.files.size(); ++i) { if (i) files += "\n"; files += js.files[i]; }
    gtk_label_set_text(GTK_LABEL(app->files_lbl), files.c_str());

    clear_listbox(app->banned_box);
    if (js.banned.empty()) {
        GtkWidget *row = gtk_label_new("No IPs currently banned.");
        gtk_widget_add_css_class(row, "dim");
        gtk_label_set_xalign(GTK_LABEL(row), 0.0);
        gtk_list_box_append(GTK_LIST_BOX(app->banned_box), row);
    }
    for (const auto &ip : js.banned) {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        gtk_widget_set_margin_top(row, 3); gtk_widget_set_margin_bottom(row, 3);
        gtk_widget_set_margin_start(row, 8); gtk_widget_set_margin_end(row, 8);
        GtkWidget *iplbl = gtk_label_new(ip.c_str());
        gtk_label_set_xalign(GTK_LABEL(iplbl), 0.0);
        gtk_widget_set_hexpand(iplbl, TRUE);
        gtk_widget_add_css_class(iplbl, "mono");
        GtkWidget *unban = gtk_button_new_with_label("Unban");
        gtk_widget_add_css_class(unban, "allow");
        IpJail *ij = new IpJail{app, ip, app->selected_jail};
        g_object_set_data_full(G_OBJECT(unban), "ij", ij,
                               [](gpointer p){ delete (IpJail *)p; });
        g_signal_connect(unban, "clicked", G_CALLBACK(on_unban_clicked), nullptr);
        gtk_box_append(GTK_BOX(row), iplbl);
        gtk_box_append(GTK_BOX(row), unban);
        gtk_list_box_append(GTK_LIST_BOX(app->banned_box), row);
    }
}

static void on_jail_selected(GtkListBox *, GtkListBoxRow *row, gpointer data) {
    App *app = (App *)data;
    if (!row) { app->selected_jail.clear(); update_detail(app); return; }
    const char *name = (const char *)g_object_get_data(G_OBJECT(row), "jail");
    app->selected_jail = name ? name : "";
    load_jail_config(app);
    update_detail(app);
}

// ---------------------------------------------------------------------------
// Refresh everything from the daemon
// ---------------------------------------------------------------------------
static void rebuild_jail_list(App *app) {
    // Remember selection so it survives the rebuild.
    std::string keep = app->selected_jail;
    // Silence row-selected while we clear and re-select: otherwise every refresh
    // would reload the jail's config from the server and clobber any unsaved
    // edits in the bantime/findtime/maxretry fields (and fire extra calls).
    g_signal_handlers_block_by_func(app->jails_box, (gpointer)on_jail_selected, app);
    clear_listbox(app->jails_box);

    GtkListBoxRow *to_select = nullptr;
    for (const auto &j : app->jails) {
        JailStatus &js = app->cache[j];
        GtkWidget *rowbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_set_margin_top(rowbox, 5); gtk_widget_set_margin_bottom(rowbox, 5);
        gtk_widget_set_margin_start(rowbox, 8); gtk_widget_set_margin_end(rowbox, 8);
        GtkWidget *name = gtk_label_new(j.c_str());
        gtk_label_set_xalign(GTK_LABEL(name), 0.0);
        gtk_widget_set_hexpand(name, TRUE);
        char badge[32]; snprintf(badge, sizeof(badge), "%d", js.cur_banned);
        GtkWidget *cnt = gtk_label_new(badge);
        gtk_widget_add_css_class(cnt, js.cur_banned > 0 ? "deny" : "dim");
        gtk_box_append(GTK_BOX(rowbox), name);
        gtk_box_append(GTK_BOX(rowbox), cnt);

        GtkWidget *row = gtk_list_box_row_new();
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), rowbox);
        g_object_set_data_full(G_OBJECT(row), "jail", g_strdup(j.c_str()), g_free);
        gtk_list_box_append(GTK_LIST_BOX(app->jails_box), row);
        if (j == keep) to_select = GTK_LIST_BOX_ROW(row);
    }
    if (to_select)
        gtk_list_box_select_row(GTK_LIST_BOX(app->jails_box), to_select);
    else
        app->selected_jail.clear();
    g_signal_handlers_unblock_by_func(app->jails_box, (gpointer)on_jail_selected, app);
}

static void rebuild_allbanned(App *app) {
    clear_listbox(app->allbanned_box);
    int total = 0;
    for (const auto &j : app->jails) {
        for (const auto &ip : app->cache[j].banned) {
            ++total;
            GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
            gtk_widget_set_margin_top(row, 3); gtk_widget_set_margin_bottom(row, 3);
            gtk_widget_set_margin_start(row, 8); gtk_widget_set_margin_end(row, 8);
            GtkWidget *iplbl = gtk_label_new(ip.c_str());
            gtk_label_set_xalign(GTK_LABEL(iplbl), 0.0);
            gtk_widget_set_size_request(iplbl, 160, -1);
            gtk_widget_add_css_class(iplbl, "mono");
            GtkWidget *jlbl = gtk_label_new(j.c_str());
            gtk_label_set_xalign(GTK_LABEL(jlbl), 0.0);
            gtk_widget_set_hexpand(jlbl, TRUE);
            gtk_widget_add_css_class(jlbl, "dim");
            GtkWidget *unban = gtk_button_new_with_label("Unban");
            gtk_widget_add_css_class(unban, "allow");
            IpJail *ij = new IpJail{app, ip, j};
            g_object_set_data_full(G_OBJECT(unban), "ij", ij,
                                   [](gpointer p){ delete (IpJail *)p; });
            g_signal_connect(unban, "clicked", G_CALLBACK(on_unban_clicked), nullptr);
            gtk_box_append(GTK_BOX(row), iplbl);
            gtk_box_append(GTK_BOX(row), jlbl);
            gtk_box_append(GTK_BOX(row), unban);
            gtk_list_box_append(GTK_LIST_BOX(app->allbanned_box), row);
        }
    }
    if (total == 0) {
        GtkWidget *row = gtk_label_new("No IPs currently banned in any jail.");
        gtk_widget_add_css_class(row, "dim");
        gtk_list_box_append(GTK_LIST_BOX(app->allbanned_box), row);
    }
}

static void rebuild_jail_dropdown(App *app) {
    // Remember the current pick by name so the periodic rebuild doesn't silently
    // reset the "Ban in jail" target back to the first jail.
    std::string sel;
    GObject *item = (GObject *)gtk_drop_down_get_selected_item(GTK_DROP_DOWN(app->gban_jail));
    if (item) sel = gtk_string_object_get_string(GTK_STRING_OBJECT(item));

    // Replace the dropdown's string model with the current jail names.
    guint old = g_list_model_get_n_items(G_LIST_MODEL(app->gban_model));
    for (guint i = 0; i < old; ++i)
        gtk_string_list_remove(app->gban_model, 0);
    for (const auto &j : app->jails)
        gtk_string_list_append(app->gban_model, j.c_str());

    if (!sel.empty())
        for (guint i = 0; i < app->jails.size(); ++i)
            if (app->jails[i] == sel) {
                gtk_drop_down_set_selected(GTK_DROP_DOWN(app->gban_jail), i);
                break;
            }
}

static void refresh_all(App *app) {
    F2BResult st = f2b_call(app, {"status"});
    if (!st.ok) {
        set_status(app, "Not authorized — click Authorize", "bad");
        gtk_widget_set_visible(app->authorize_btn, TRUE);
        return;
    }
    gtk_widget_set_visible(app->authorize_btn, FALSE);

    if (st.rc != 0) {
        set_status(app, "fail2ban server not responding", "bad");
        app->jails.clear(); app->cache.clear();
        rebuild_jail_list(app); rebuild_allbanned(app);
        rebuild_jail_dropdown(app); update_detail(app);
        return;
    }

    app->jails = parse_jail_list(st.out);
    std::sort(app->jails.begin(), app->jails.end());

    std::map<std::string, JailStatus> fresh;
    for (const auto &j : app->jails) {
        F2BResult js = f2b_call(app, {"status", j});
        if (js.ok && js.rc == 0) fresh[j] = parse_jail_status(js.out);
        else fresh[j] = JailStatus{};
    }
    app->cache.swap(fresh);

    // Version line for the status label.
    static std::string ver;
    if (ver.empty()) { F2BResult v = f2b_call(app, {"version"}); if (v.ok) ver = trim(v.out); }

    int total_banned = 0;
    for (auto &kv : app->cache) total_banned += kv.second.cur_banned;
    char buf[160];
    snprintf(buf, sizeof(buf), "Server running · v%s · %zu jail%s · %d banned",
             ver.empty() ? F2B_VERSION : ver.c_str(),
             app->jails.size(), app->jails.size() == 1 ? "" : "s", total_banned);
    set_status(app, buf, "ok");

    rebuild_jail_list(app);
    rebuild_jail_dropdown(app);
    rebuild_allbanned(app);
    update_detail(app);
}

static gboolean refresh_tick(gpointer data) {
    App *app = (App *)data;
    if (app->auth_ok) refresh_all(app);   // stay quiet until the user has authorised
    return G_SOURCE_CONTINUE;
}

// ---------------------------------------------------------------------------
// About dialog
// ---------------------------------------------------------------------------
static void on_about_clicked(GtkButton *, gpointer data) {
    App *app = (App *)data;
    GtkAboutDialog *about = GTK_ABOUT_DIALOG(gtk_about_dialog_new());
    gtk_window_set_transient_for(GTK_WINDOW(about), GTK_WINDOW(app->window));
    gtk_window_set_modal(GTK_WINDOW(about), TRUE);
    gtk_about_dialog_set_program_name(about, "Fail2ban GUI");
    gtk_about_dialog_set_version(about, F2B_VERSION);
    gtk_about_dialog_set_logo_icon_name(about, "fail2ban-gui");
    gtk_about_dialog_set_comments(about,
        "A graphical front-end for fail2ban.\n"
        "Manage jails, bans and the server without the command line.");
    gtk_about_dialog_set_website(about, "https://github.com/effjy/fail2ban-gui/");
    gtk_about_dialog_set_website_label(about, "Repository");
    gtk_about_dialog_set_license_type(about, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_copyright(about, "© 2026 Jean-Francois Lachance-Caumartin");
    const char *authors[] = { "Jean-Francois Lachance-Caumartin", nullptr };
    gtk_about_dialog_set_authors(about, authors);
    gtk_window_present(GTK_WINDOW(about));
}

// ---------------------------------------------------------------------------
// Theme (Tokyo Night)
// ---------------------------------------------------------------------------
static const char *CSS =
    "window { background-color: #1a1b26; color: #c0caf5; }"
    ".title { font-weight: bold; font-size: 18px; color: #7aa2f7; }"
    ".sub   { color: #565f89; font-size: 11px; }"
    ".ok    { color: #9ece6a; font-size: 12px; }"
    ".bad   { color: #f7768e; font-size: 12px; }"
    ".dim   { color: #565f89; }"
    ".mono  { font-family: monospace; color: #a9b1d6; }"
    ".panelhead { font-size: 15px; font-weight: bold; color: #7aa2f7; }"
    ".section   { color: #565f89; font-size: 11px; font-weight: bold; }"
    ".statnum { font-size: 20px; font-weight: bold; color: #c0caf5; }"
    ".statcap { color: #565f89; font-size: 10px; }"
    "textview, textview text { background-color: #16161e; color: #a9b1d6;"
    "  font-family: monospace; font-size: 12px; }"
    "list, row { background-color: #16161e; }"
    "entry { background: #16161e; color: #c0caf5; border: 1px solid #414868;"
    "  border-radius: 6px; padding: 4px 8px; }"
    "button { background: #24283b; color: #c0caf5; border: 1px solid #414868;"
    "  border-radius: 6px; padding: 6px 12px; }"
    "button:hover { background: #2f344d; }"
    "button:disabled { color: #565f89; border-color: #2a2e42; }"
    "button.allow { color: #9ece6a; border-color: #9ece6a; }"
    "button.allow:hover { background: #9ece6a; color: #16161e; }"
    "button.deny { color: #f7768e; border-color: #f7768e; }"
    "button.deny:hover { background: #f7768e; color: #16161e; }"
    ".allow { color: #9ece6a; font-weight: bold; }"
    ".deny  { color: #f7768e; font-weight: bold; }";

static void apply_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_string(p, CSS);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

// ---------------------------------------------------------------------------
// Tray + window behaviour (same approach as Warden)
// ---------------------------------------------------------------------------
static bool g_tray_active = false;

static void present_front(App *app) {
    if (!app->window) return;
    gtk_widget_set_visible(app->window, TRUE);
    gtk_window_unminimize(GTK_WINDOW(app->window));
#ifdef GDK_WINDOWING_X11
    GdkSurface *surf = gtk_native_get_surface(GTK_NATIVE(app->window));
    if (surf && GDK_IS_X11_SURFACE(surf))
        gdk_x11_surface_set_user_time(surf, gdk_x11_get_server_time(surf));
#endif
    gtk_window_present(GTK_WINDOW(app->window));
}

static void tray_show_cb(void *user) { present_front((App *)user); }
static void tray_quit_cb(void *user) {
    App *app = (App *)user;
    g_application_quit(G_APPLICATION(app->app));
}

static gboolean on_window_close(GtkWindow *win, gpointer) {
    if (g_tray_active) { gtk_widget_set_visible(GTK_WIDGET(win), FALSE); return TRUE; }
    return FALSE;
}
static void on_surface_state(GdkToplevel *tl, GParamSpec *, gpointer data) {
    App *app = (App *)data;
    if (!g_tray_active || !app->window) return;
    if (gdk_toplevel_get_state(tl) & GDK_TOPLEVEL_STATE_MINIMIZED)
        gtk_widget_set_visible(app->window, FALSE);
}
static void on_window_realize(GtkWidget *w, gpointer data) {
    GdkSurface *s = gtk_native_get_surface(GTK_NATIVE(w));
    if (s && GDK_IS_TOPLEVEL(s))
        g_signal_connect(s, "notify::state", G_CALLBACK(on_surface_state), data);
}

// ---------------------------------------------------------------------------
// Page builders
// ---------------------------------------------------------------------------
static GtkWidget *labelled_entry(const char *cap, GtkWidget **entry_out) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *c = gtk_label_new(cap);
    gtk_widget_add_css_class(c, "statcap");
    gtk_label_set_xalign(GTK_LABEL(c), 0.0);
    GtkWidget *e = gtk_entry_new();
    gtk_widget_set_size_request(e, 90, -1);
    gtk_box_append(GTK_BOX(box), c);
    gtk_box_append(GTK_BOX(box), e);
    *entry_out = e;
    return box;
}

static GtkWidget *build_jails_page(App *app) {
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

    // Left: jail list
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_top(left, 8); gtk_widget_set_margin_bottom(left, 8);
    gtk_widget_set_margin_start(left, 8); gtk_widget_set_margin_end(left, 4);
    gtk_widget_set_size_request(left, 210, -1);
    GtkWidget *lcap = gtk_label_new("JAILS");
    gtk_widget_add_css_class(lcap, "section");
    gtk_label_set_xalign(GTK_LABEL(lcap), 0.0);
    gtk_box_append(GTK_BOX(left), lcap);
    app->jails_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app->jails_box), GTK_SELECTION_SINGLE);
    g_signal_connect(app->jails_box, "row-selected", G_CALLBACK(on_jail_selected), app);
    GtkWidget *jscroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(jscroll), app->jails_box);
    gtk_widget_set_vexpand(jscroll, TRUE);
    gtk_box_append(GTK_BOX(left), jscroll);
    gtk_box_append(GTK_BOX(page), left);

    // Right: detail
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(right, 8); gtk_widget_set_margin_bottom(right, 8);
    gtk_widget_set_margin_start(right, 4); gtk_widget_set_margin_end(right, 8);
    gtk_widget_set_hexpand(right, TRUE);

    app->detail_title = gtk_label_new("Select a jail");
    gtk_widget_add_css_class(app->detail_title, "panelhead");
    gtk_label_set_xalign(GTK_LABEL(app->detail_title), 0.0);
    gtk_box_append(GTK_BOX(right), app->detail_title);

    // Stats row
    GtkWidget *stats = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_append(GTK_BOX(stats), make_stat("currently banned", &app->st_curban));
    gtk_box_append(GTK_BOX(stats), make_stat("total banned",     &app->st_totban));
    gtk_box_append(GTK_BOX(stats), make_stat("currently failed", &app->st_curfail));
    gtk_box_append(GTK_BOX(stats), make_stat("total failed",     &app->st_totfail));
    gtk_box_append(GTK_BOX(right), stats);

    // Watched files
    GtkWidget *fcap = gtk_label_new("WATCHED LOG FILES");
    gtk_widget_add_css_class(fcap, "section");
    gtk_label_set_xalign(GTK_LABEL(fcap), 0.0);
    gtk_box_append(GTK_BOX(right), fcap);
    app->files_lbl = gtk_label_new("");
    gtk_widget_add_css_class(app->files_lbl, "mono");
    gtk_label_set_xalign(GTK_LABEL(app->files_lbl), 0.0);
    gtk_label_set_wrap(GTK_LABEL(app->files_lbl), TRUE);
    gtk_box_append(GTK_BOX(right), app->files_lbl);

    // Config row
    GtkWidget *ccap = gtk_label_new("CONFIGURATION");
    gtk_widget_add_css_class(ccap, "section");
    gtk_label_set_xalign(GTK_LABEL(ccap), 0.0);
    gtk_box_append(GTK_BOX(right), ccap);
    GtkWidget *cfg = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_append(GTK_BOX(cfg), labelled_entry("bantime (s)",  &app->ent_bantime));
    gtk_box_append(GTK_BOX(cfg), labelled_entry("findtime (s)", &app->ent_findtime));
    gtk_box_append(GTK_BOX(cfg), labelled_entry("maxretry",     &app->ent_maxretry));
    GtkWidget *applybtn = gtk_button_new_with_label("Apply");
    gtk_widget_set_valign(applybtn, GTK_ALIGN_END);
    g_signal_connect(applybtn, "clicked", G_CALLBACK(on_apply_config), app);
    gtk_box_append(GTK_BOX(cfg), applybtn);
    gtk_box_append(GTK_BOX(right), cfg);

    // Banned IPs list
    GtkWidget *bcap = gtk_label_new("BANNED IPs");
    gtk_widget_add_css_class(bcap, "section");
    gtk_label_set_xalign(GTK_LABEL(bcap), 0.0);
    gtk_box_append(GTK_BOX(right), bcap);
    app->banned_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app->banned_box), GTK_SELECTION_NONE);
    GtkWidget *bscroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(bscroll), app->banned_box);
    gtk_widget_set_vexpand(bscroll, TRUE);
    gtk_box_append(GTK_BOX(right), bscroll);

    // Ban / unban-all / jail control row
    app->detail_actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    app->ent_banip = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->ent_banip), "IP address");
    gtk_widget_set_hexpand(app->ent_banip, TRUE);
    GtkWidget *banbtn = gtk_button_new_with_label("Ban");
    gtk_widget_add_css_class(banbtn, "deny");
    g_signal_connect(banbtn, "clicked", G_CALLBACK(on_jail_banip), app);
    GtkWidget *unall = gtk_button_new_with_label("Unban all");
    gtk_widget_add_css_class(unall, "allow");
    g_signal_connect(unall, "clicked", G_CALLBACK(on_jail_unban_all), app);
    GtkWidget *startb = gtk_button_new_with_label("Start");
    g_signal_connect(startb, "clicked", G_CALLBACK(on_jail_start), app);
    GtkWidget *stopb = gtk_button_new_with_label("Stop");
    g_signal_connect(stopb, "clicked", G_CALLBACK(on_jail_stop), app);
    GtkWidget *reloadb = gtk_button_new_with_label("Reload");
    g_signal_connect(reloadb, "clicked", G_CALLBACK(on_jail_reload), app);

    // First row: ban entry. The entry lives outside detail_actions so it stays
    // usable; the buttons go in detail_actions for sensitivity toggling.
    GtkWidget *banrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(banrow), app->ent_banip);
    gtk_box_append(GTK_BOX(app->detail_actions), banbtn);
    gtk_box_append(GTK_BOX(app->detail_actions), unall);
    gtk_box_append(GTK_BOX(app->detail_actions), startb);
    gtk_box_append(GTK_BOX(app->detail_actions), stopb);
    gtk_box_append(GTK_BOX(app->detail_actions), reloadb);
    gtk_box_append(GTK_BOX(banrow), app->detail_actions);
    gtk_box_append(GTK_BOX(right), banrow);

    gtk_box_append(GTK_BOX(page), right);
    return page;
}

static GtkWidget *build_banned_page(App *app) {
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_top(page, 8); gtk_widget_set_margin_bottom(page, 8);
    gtk_widget_set_margin_start(page, 8); gtk_widget_set_margin_end(page, 8);

    GtkWidget *cap = gtk_label_new("ALL BANNED IPs");
    gtk_widget_add_css_class(cap, "section");
    gtk_label_set_xalign(GTK_LABEL(cap), 0.0);
    gtk_box_append(GTK_BOX(page), cap);

    app->allbanned_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app->allbanned_box), GTK_SELECTION_NONE);
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), app->allbanned_box);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(page), scroll);

    // Manual ban: IP + jail dropdown + Ban
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    app->ent_gban_ip = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->ent_gban_ip), "IP address to ban");
    gtk_widget_set_hexpand(app->ent_gban_ip, TRUE);
    app->gban_model = gtk_string_list_new(nullptr);
    app->gban_jail = gtk_drop_down_new(G_LIST_MODEL(app->gban_model), nullptr);
    GtkWidget *gbanbtn = gtk_button_new_with_label("Ban in jail");
    gtk_widget_add_css_class(gbanbtn, "deny");
    g_signal_connect(gbanbtn, "clicked", G_CALLBACK(on_global_ban), app);
    gtk_box_append(GTK_BOX(row), app->ent_gban_ip);
    gtk_box_append(GTK_BOX(row), app->gban_jail);
    gtk_box_append(GTK_BOX(row), gbanbtn);
    gtk_box_append(GTK_BOX(page), row);
    return page;
}

static GtkWidget *build_log_page(App *app) {
    app->log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->log_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app->log_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app->log_view), TRUE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app->log_view), 8);
    GtkTextBuffer *lb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->log_view));
    GtkTextIter e; gtk_text_buffer_get_end_iter(lb, &e);
    app->log_end = gtk_text_buffer_create_mark(lb, "log-end", &e, FALSE);
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), app->log_view);
    gtk_widget_set_vexpand(scroll, TRUE);
    return scroll;
}

// ---------------------------------------------------------------------------
// Window construction
// ---------------------------------------------------------------------------
static void activate(GtkApplication *gapp, gpointer data) {
    App *app = (App *)data;
    if (app->window) { present_front(app); return; }

    apply_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "Fail2ban GUI");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 860, 600);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "fail2ban-gui");

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(GTK_WINDOW(app->window), root);

    // Header
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_top(header, 12); gtk_widget_set_margin_bottom(header, 10);
    gtk_widget_set_margin_start(header, 16); gtk_widget_set_margin_end(header, 16);
    GtkWidget *titlebox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *title = gtk_label_new("FAIL2BAN GUI");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_add_css_class(title, "title");
    app->status_lbl = gtk_label_new("Connecting…");
    gtk_label_set_xalign(GTK_LABEL(app->status_lbl), 0.0);
    gtk_widget_add_css_class(app->status_lbl, "sub");
    gtk_box_append(GTK_BOX(titlebox), title);
    gtk_box_append(GTK_BOX(titlebox), app->status_lbl);
    gtk_widget_set_hexpand(titlebox, TRUE);
    gtk_box_append(GTK_BOX(header), titlebox);

    app->authorize_btn = gtk_button_new_with_label("Authorize");
    gtk_widget_add_css_class(app->authorize_btn, "allow");
    gtk_widget_set_valign(app->authorize_btn, GTK_ALIGN_CENTER);
    gtk_widget_set_visible(app->authorize_btn, FALSE);
    g_signal_connect(app->authorize_btn, "clicked", G_CALLBACK(on_authorize), app);
    gtk_box_append(GTK_BOX(header), app->authorize_btn);

    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    g_signal_connect(refresh, "clicked", G_CALLBACK(on_refresh_clicked), app);
    gtk_widget_set_valign(refresh, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(header), refresh);

    GtkWidget *reloadsrv = gtk_button_new_with_label("Reload");
    g_signal_connect(reloadsrv, "clicked", G_CALLBACK(on_server_reload), app);
    gtk_widget_set_valign(reloadsrv, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(header), reloadsrv);

    GtkWidget *restartsrv = gtk_button_new_with_label("Restart");
    gtk_widget_add_css_class(restartsrv, "deny");
    g_signal_connect(restartsrv, "clicked", G_CALLBACK(on_server_restart), app);
    gtk_widget_set_valign(restartsrv, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(header), restartsrv);

    GtkWidget *about = gtk_button_new_with_label("About");
    g_signal_connect(about, "clicked", G_CALLBACK(on_about_clicked), app);
    gtk_widget_set_valign(about, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(header), about);
    gtk_box_append(GTK_BOX(root), header);

    // Tabs
    GtkWidget *stack = gtk_stack_new();
    GtkWidget *switcher = gtk_stack_switcher_new();
    gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(switcher), GTK_STACK(stack));
    gtk_widget_set_halign(switcher, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(root), switcher);

    gtk_stack_add_titled(GTK_STACK(stack), build_jails_page(app),  "jails",  "Jails");
    gtk_stack_add_titled(GTK_STACK(stack), build_banned_page(app), "banned", "Banned IPs");
    gtk_stack_add_titled(GTK_STACK(stack), build_log_page(app),    "log",    "Activity");
    gtk_widget_set_vexpand(stack, TRUE);
    gtk_box_append(GTK_BOX(root), stack);

    update_detail(app);   // start in the "select a jail" state

    // Tray: closing/minimizing hides to tray when one is present.
    g_tray_active = tray_init(G_APPLICATION(gapp), "fail2ban-gui",
                              tray_show_cb, tray_quit_cb, app);
    g_signal_connect(app->window, "close-request", G_CALLBACK(on_window_close), app);
    g_signal_connect(app->window, "realize", G_CALLBACK(on_window_realize), app);

    log_append(app, "Fail2ban GUI " F2B_VERSION " started.");
    if (g_tray_active)
        log_append(app, "Tray icon active — minimizing or closing sends the window to the tray.");
    log_append(app, "Authorizing with pkexec to reach fail2ban…");

    present_front(app);

    // First refresh triggers the single pkexec authorisation prompt.
    refresh_all(app);
    g_timeout_add_seconds(8, refresh_tick, app);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--helper") == 0)
        return helper_main();

    signal(SIGPIPE, SIG_IGN);   // writing to a dead helper must not kill us

    App app;
    app.app = gtk_application_new("com.github.effjy.fail2ban_gui", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app.app, "activate", G_CALLBACK(activate), &app);
    int status = g_application_run(G_APPLICATION(app.app), argc, argv);
    helper_shutdown(&app);
    g_object_unref(app.app);
    return status;
}
