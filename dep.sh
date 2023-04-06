# ROOT_dir = `PWD`
# cd ${ROOT_dir}/3rdparty
# # git clone https://ghproxy.com/https://github.com/gabime/spdlog.git
# cd spdlog && mkdir build && cd build
# cmake .. && mkdir -j
# cp libspdlog.a ${ROOT_dir}/lib/

# cd ${ROOT_dir}/3rdparty
# # git clone https://ghproxy.com/https://github.com/fmtlib/fmt.git
# cd fmt && mkdir build && cd build
# cmake .. && mkdir -j
# cp libfmt.a ${ROOT_dir}/lib/

sudo apt install libfmt-dev libspdlog-dev libelf-dev libbpf-dev clang cmake
# linux-oem-5.6-tools-common

# cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 .