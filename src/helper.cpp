// helper.cpp — privileged co-process: runs fail2ban-client as root.
//
// Wire protocol (newline-framed text on the helper's stdin/stdout):
//
//   request   <n>\n            number of argv tokens that follow
//             <arg0>\n         each token on its own line (tokens never
//             <arg1>\n         contain a newline — the GUI guarantees this)
//             ...
//   response  <rc> <len>\n     fail2ban-client exit status, then byte count
//             <len bytes>      combined stdout+stderr, verbatim
//
// The first token must be a known fail2ban-client verb (helper_arg_allowed),
// otherwise the helper replies rc=126 with an error message and runs nothing.
//
// Author: Jean-Francois Lachance-Caumartin
#include "helper.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

static const char *FAIL2BAN_CLIENT = "/usr/bin/fail2ban-client";

bool helper_arg_allowed(const std::string &verb) {
    // Every fail2ban-client subcommand the GUI ever issues. "set" covers
    // ban/unban and per-jail config writes; "get" covers config reads.
    static const char *ok[] = {
        "status", "get", "set", "start", "stop", "reload", "restart",
        "ping", "version", "banned", "unban", nullptr
    };
    for (int i = 0; ok[i]; ++i)
        if (verb == ok[i]) return true;
    return false;
}

// Read exactly one line (without the trailing '\n') from fd 0. Returns false on
// EOF before any byte was read.
static bool read_line(std::string &out) {
    out.clear();
    char c;
    ssize_t n;
    bool got = false;
    while ((n = read(0, &c, 1)) == 1) {
        got = true;
        if (c == '\n') return true;
        out += c;
    }
    return got;  // last line may be unterminated; n<=0 ends the stream
}

static bool write_all(int fd, const char *p, size_t len) {
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return false;
        p += n; len -= (size_t)n;
    }
    return true;
}

// Run fail2ban-client with argv, capture stdout+stderr together, return exit
// code (or 127 if it could not be launched).
static int run_client(const std::vector<std::string> &args, std::string &output) {
    int pipefd[2];
    if (pipe(pipefd) != 0) { output = "helper: pipe() failed\n"; return 127; }

    pid_t pid = fork();
    if (pid < 0) { output = "helper: fork() failed\n"; close(pipefd[0]); close(pipefd[1]); return 127; }

    if (pid == 0) {
        // Child: stdout+stderr -> pipe, then exec fail2ban-client directly.
        dup2(pipefd[1], 1);
        dup2(pipefd[1], 2);
        close(pipefd[0]);
        close(pipefd[1]);

        std::vector<char *> argv;
        argv.push_back((char *)FAIL2BAN_CLIENT);
        for (const auto &a : args) argv.push_back(const_cast<char *>(a.c_str()));
        argv.push_back(nullptr);
        execv(FAIL2BAN_CLIENT, argv.data());
        // Only reached if exec failed.
        const char *msg = "helper: cannot exec fail2ban-client\n";
        if (write(1, msg, strlen(msg)) < 0) { /* nothing we can do */ }
        _exit(127);
    }

    // Parent: drain the pipe.
    close(pipefd[1]);
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
        output.append(buf, (size_t)n);
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

int helper_main() {
    std::string head;
    while (read_line(head)) {
        if (head.empty()) continue;
        int count = atoi(head.c_str());
        if (count < 1 || count > 64) {
            // Malformed frame — drain nothing, report and continue.
            const char *e = "helper: bad request frame\n";
            char hdr[64]; int hl = snprintf(hdr, sizeof(hdr), "126 %zu\n", strlen(e));
            write_all(1, hdr, (size_t)hl); write_all(1, e, strlen(e));
            continue;
        }
        std::vector<std::string> args;
        bool ok = true;
        for (int i = 0; i < count; ++i) {
            std::string a;
            if (!read_line(a)) { ok = false; break; }
            args.push_back(a);
        }
        if (!ok) break;

        std::string output;
        int rc;
        if (args.empty() || !helper_arg_allowed(args[0])) {
            output = "helper: command not permitted: " + (args.empty() ? "" : args[0]) + "\n";
            rc = 126;
        } else {
            rc = run_client(args, output);
        }

        char hdr[64];
        int hl = snprintf(hdr, sizeof(hdr), "%d %zu\n", rc, output.size());
        if (!write_all(1, hdr, (size_t)hl)) break;
        if (!write_all(1, output.data(), output.size())) break;
    }
    return 0;
}
