// Copyright (C) 2024  Niels Martignène <niels.martignene@protonmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "src/core/base/base.hh"
#include "zygote.hh"
#include "src/core/sandbox/sandbox.hh"
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

namespace RG {

static int main_pfd[2] = { -1, -1 };

static bool ApplySandbox(Span<const char *const> reveal_paths)
{
    if (!sb_IsSandboxSupported()) {
        LogError("Sandbox mode is not supported on this platform");
        return false;
    }

    sb_SandboxBuilder sb;

    sb.RevealPaths(reveal_paths, true);

#if defined(__linux__)
    sb.FilterSyscalls({
        { "exit", sb_FilterAction::Allow },
        { "exit_group", sb_FilterAction::Allow },
        { "brk", sb_FilterAction::Allow },
        { "mmap/anon", sb_FilterAction ::Allow},
        { "mmap/shared", sb_FilterAction ::Allow},
        { "munmap", sb_FilterAction::Allow },
        { "mremap", sb_FilterAction::Allow },
        { "mprotect/noexec", sb_FilterAction ::Allow},
        { "mlock", sb_FilterAction::Allow },
        { "mlock2", sb_FilterAction::Allow },
        { "mlockall", sb_FilterAction::Allow },
        { "madvise", sb_FilterAction::Allow },
        { "pipe", sb_FilterAction::Allow },
        { "pipe2", sb_FilterAction::Allow },
        { "open", sb_FilterAction::Allow },
        { "openat", sb_FilterAction::Allow },
        { "openat2", sb_FilterAction::Allow },
        { "close", sb_FilterAction::Allow },
        { "fcntl", sb_FilterAction::Allow },
        { "read", sb_FilterAction::Allow },
        { "readv", sb_FilterAction::Allow },
        { "write", sb_FilterAction::Allow },
        { "writev", sb_FilterAction::Allow },
        { "pread64", sb_FilterAction::Allow },
        { "pwrite64", sb_FilterAction::Allow },
        { "lseek", sb_FilterAction::Allow },
        { "ftruncate", sb_FilterAction::Allow },
        { "fsync", sb_FilterAction::Allow },
        { "fdatasync", sb_FilterAction::Allow },
        { "fstat", sb_FilterAction::Allow },
        { "stat", sb_FilterAction::Allow },
        { "lstat", sb_FilterAction::Allow },
        { "lstat64", sb_FilterAction::Allow },
        { "fstatat64", sb_FilterAction::Allow },
        { "newfstatat", sb_FilterAction::Allow },
        { "statx", sb_FilterAction::Allow },
        { "access", sb_FilterAction::Allow },
        { "ioctl/tty", sb_FilterAction ::Allow},
        { "getrandom", sb_FilterAction::Allow },
        { "getpid", sb_FilterAction::Allow },
        { "gettid", sb_FilterAction::Allow },
        { "getuid", sb_FilterAction::Allow },
        { "getgid", sb_FilterAction::Allow },
        { "geteuid", sb_FilterAction::Allow },
        { "getegid", sb_FilterAction::Allow },
        { "getcwd", sb_FilterAction::Allow },
        { "rt_sigaction", sb_FilterAction::Allow },
        { "rt_sigpending", sb_FilterAction::Allow },
        { "rt_sigprocmask", sb_FilterAction::Allow },
        { "rt_sigqueueinfo", sb_FilterAction::Allow },
        { "rt_sigreturn", sb_FilterAction::Allow },
        { "rt_sigsuspend", sb_FilterAction::Allow },
        { "rt_sigtimedwait", sb_FilterAction::Allow },
        { "rt_sigtimedwait_time64", sb_FilterAction::Allow },
        { "kill", sb_FilterAction::Allow },
        { "tgkill", sb_FilterAction::Allow },
        { "fork", sb_FilterAction::Allow },
        { "clone/fork", sb_FilterAction::Allow },
        { "futex", sb_FilterAction::Allow },
        { "futex_time64", sb_FilterAction::Allow },
        { "rseq", sb_FilterAction::Allow },
        { "set_robust_list", sb_FilterAction::Allow },
        { "getsockopt", sb_FilterAction::Allow },
        { "setsockopt", sb_FilterAction::Allow },
        { "getsockname", sb_FilterAction::Allow },
        { "getpeername", sb_FilterAction::Allow },
        { "getdents", sb_FilterAction::Allow },
        { "getdents64", sb_FilterAction::Allow },
        { "prctl", sb_FilterAction::Allow },
        { "poll", sb_FilterAction::Allow },
        { "select", sb_FilterAction::Allow },
        { "clock_nanosleep", sb_FilterAction::Allow },
        { "clock_gettime", sb_FilterAction::Allow },
        { "clock_gettime64", sb_FilterAction::Allow },
        { "clock_nanosleep", sb_FilterAction::Allow },
        { "clock_nanosleep_time64", sb_FilterAction::Allow },
        { "nanosleep", sb_FilterAction::Allow },
        { "sched_yield", sb_FilterAction::Allow },
        { "sched_getaffinity", sb_FilterAction::Allow },
        { "recv", sb_FilterAction::Allow },
        { "recvfrom", sb_FilterAction::Allow },
        { "recvmmsg", sb_FilterAction::Allow },
        { "recvmmsg_time64", sb_FilterAction::Allow },
        { "recvmsg", sb_FilterAction::Allow },
        { "sendmsg", sb_FilterAction::Allow },
        { "sendmmsg", sb_FilterAction::Allow },
        { "sendfile", sb_FilterAction::Allow },
        { "sendfile64", sb_FilterAction::Allow },
        { "sendto", sb_FilterAction::Allow },
        { "shutdown", sb_FilterAction::Allow },
        { "uname", sb_FilterAction::Allow },
        { "utime", sb_FilterAction::Allow },
        { "getrusage", sb_FilterAction::Allow }
    });
#endif

    return sb.Apply();
}

static bool ProcessRun(struct cmsghdr *cmsg)
{
    if (!cmsg) {
        LogError("Missing ancillary data for request command");
        return false;
    }
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
                                          cmsg->cmsg_len != CMSG_LEN(RG_SIZE(int))) {
        LogError("Missing socket descriptor for request command");
        return false;
    }

    int fd = -1;
    RG_DEFER { CloseDescriptor(fd); };

    MemCpy(&fd, CMSG_DATA(cmsg), RG_SIZE(int));

    pid_t pid = fork();

    if (pid < 0) {
        LogError("Failed to fork zygote process: %1", strerror(errno));
        return false;
    }

    // Not our problem anymore, let the forked process do the rest
    if (pid > 0)
        return true;

    LogInfo("RUN!");

    return true;
}

static bool ServeRequests()
{
    for (;;) {
        uint8_t type = 0;
        uint8_t control[256];

        struct iovec iov = { &type, 1 };
        struct msghdr msg = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = control,
            .msg_controllen = RG_SIZE(control),
            .msg_flags = 0
        };

        Size ret = recvmsg(main_pfd[1], &msg, MSG_CMSG_CLOEXEC);

        if (ret < 0) {
            LogError("Failed to read from UNIX socket: %1", strerror(errno));
            return false;
        }
        if (!ret)
            break;

        switch (type) {
            case 1: {
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                ProcessRun(cmsg);
            } break;

            default: { LogError("Ignoring unknown message 0x%1 from server process", FmtHex(type)); } break;
        }
    }

    return true;
}

ZygoteResult RunZygote(bool sandbox, const char *view_directory)
{
    RG_ASSERT(main_pfd[0] < 0);

    RG_DEFER_N(pfd_guard) {
        CloseDescriptor(main_pfd[0]);
        CloseDescriptor(main_pfd[1]);

        main_pfd[0] = -1;
        main_pfd[1] = -1;
    };

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, main_pfd) < 0) {
        LogError("Failed to create UNIX socket pair: %1", strerror(errno));
        return ZygoteResult::Error;
    }

    pid_t pid = fork();

    if (pid < 0) {
        LogError("Failed to run zygote process: %1", strerror(errno));
        return ZygoteResult::Error;
    }

    if (pid > 0) {
        CloseDescriptor(main_pfd[1]);
        main_pfd[1] = -1;

        uint8_t dummy = 0;
        Size ret = recv(main_pfd[0], &dummy, RG_SIZE(dummy), 0);

        if (ret < 0) {
            LogError("Failed to read from zygote socket: %1", strerror(errno));
            return ZygoteResult::Error;
        } else if (!ret) {
            LogError("Zygote process failed to initialize");
            return ZygoteResult::Error;
        }

        atexit([]() { CloseDescriptor(main_pfd[0]); });
        pfd_guard.Disable();

        return ZygoteResult::Parent;
    } else {
        CloseDescriptor(main_pfd[0]);
        main_pfd[0] = -1;

        if (sandbox) {
            const char *const reveal_paths[] = {
                view_directory
            };

            if (!ApplySandbox(reveal_paths))
                return ZygoteResult::Error;
        }

        // I'm ready!
        uint8_t dummy = 0;
        Size ret = send(main_pfd[1], &dummy, RG_SIZE(dummy), MSG_NOSIGNAL);

        if (ret < 0) {
            LogError("Failed to write to zygote socket: %1", strerror(errno));
            return ZygoteResult::Error;
        }
        RG_ASSERT(ret);

        if (!ServeRequests())
            return ZygoteResult::Error;

        return ZygoteResult::Child;
    }
}

bool RunScript()
{
    RG_ASSERT(main_pfd[0] >= 0);
    RG_ASSERT(main_pfd[1] < 0);

    // Create socket pair
    int pfd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pfd) < 0) {
        LogError("Failed to create UNIX socket pair: %1", strerror(errno));
        return false;
    }
    RG_DEFER {
        CloseDescriptor(pfd[0]);
        CloseDescriptor(pfd[1]);
    };

    // Send request and connection to zygote
    {
        uint8_t type = 1;
        uint8_t control[CMSG_SPACE(RG_SIZE(int))] = {};

        struct iovec iov = { &type, 1 };
        struct msghdr msg = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = control,
            .msg_controllen = RG_SIZE(control),
            .msg_flags = 0
        };

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        RG_ASSERT(cmsg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(RG_SIZE(int));
        MemCpy(CMSG_DATA(cmsg), &pfd[1], RG_SIZE(int));

        if (sendmsg(main_pfd[0], &msg, MSG_NOSIGNAL) < 0) {
            LogError("Failed to send run request to zygote: %1 %2", strerror(errno), pfd[1]);
            return false;
        }

        CloseDescriptor(pfd[1]);
        pfd[1] = -1;
    }

    // Do somethng with pfd[0]!

    return true;
}

}
