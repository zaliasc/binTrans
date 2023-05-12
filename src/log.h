#include <fmt/core.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>

#define SPDLOG_NAME "mylogger"

// #define DEBUG

#define LOG(string) spdlog::info(fmt::format("{0}", string))

// #define INSN(inst, buf) spdlog::info(fmt::format("{0:08x}   {1}", inst, buf))
// #define INSN(buf) spdlog::info(fmt::format("{0}", buf))
#define INSN_ADDR(inst, buf) spdlog::info(fmt::format("{0:08x} :  {1}", inst, buf))
#define INSN_DISASSEMBLY(buf) spdlog::info(fmt::format("{0}", buf))