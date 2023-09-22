// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#include "src/core/libcc/libcc.hh"
#include "eggc.hh"
#include "src/core/libsandbox/libsandbox.hh"

namespace RG {

static void DumpTokens(Span<const bk_Token> tokens)
{
    for (const bk_Token &token: tokens) {
        PrintLn("%1 (%2:%3)", bk_TokenKindNames[(int)token.kind], token.line, token.offset);
    }
}

int RunCommand(Span<const char> code, const Config &config)
{
    bk_TokenizedFile file;
    if (!bk_Tokenize(code, "<inline>", &file))
        return 1;

    DumpTokens(file.tokens);
    return 0;
}

int RunFile(const char *filename, const Config &config)
{
    HeapArray<char> code;
    if (ReadFile(filename, Megabytes(256), &code) < 0)
        return 1;

    bk_TokenizedFile file;
    if (!bk_Tokenize(code, filename, &file))
        return 1;

    DumpTokens(file.tokens);
    return 0;
}

int Main(int argc, char **argv)
{
    RG_CRITICAL(argc >= 1, "First argument is missing");

    enum class RunMode {
        File,
        Command
    };

    // Options
    RunMode mode = RunMode::File;
    const char *filename_or_code = nullptr;
    Config config;

    const auto print_usage = [](FILE *fp) {
        PrintLn(fp, R"(Usage: %!..+%1 [options] <file>
       %1 [options] -c <code>

Options:
    %!..+-c, --command%!0                Run code directly from argument

        %!..+--no_execute%!0             Parse code but don't run it
        %!..+--no_expression%!0          Don't try to run code as expression
                                 %!D..(works only with -c or -i)%!0
        %!..+--debug%!0                  Dump executed VM instructions)", FelixTarget);
    };

    // Handle version
    if (argc >= 2 && TestStr(argv[1], "--version")) {
        PrintLn("%!R..%1%!0 %!..+%2%!0", FelixTarget, FelixVersion);
        PrintLn("Compiler: %1", FelixCompiler);
        return 0;
    }

    // Parse arguments
    {
        OptionParser opt(argc, argv);

        while (opt.Next()) {
            if (opt.Test("--help")) {
                print_usage(stdout);
                return 0;
            } else if (opt.Test("-c", "--command")) {
                mode = RunMode::Command;
            } else if (opt.Test("--no_execute")) {
                config.execute = false;
            } else if (opt.Test("--debug")) {
                config.debug = true;
            } else {
                opt.LogUnknownError();
                return 1;
            }
        }

        filename_or_code = opt.ConsumeNonOption();
    }

    switch (mode) {
        case RunMode::File: {
            if (!filename_or_code) {
                LogError("No filename provided");
                return 1;
            }

            return RunFile(filename_or_code, config);
        } break;
        case RunMode::Command: {
            if (!filename_or_code) {
                LogError("No command provided");
                return 1;
            }

            return RunCommand(filename_or_code, config);
        } break;
    }

    RG_UNREACHABLE();
}

}

// C++ namespaces are stupid
int main(int argc, char **argv) { return RG::RunApp(argc, argv); }
