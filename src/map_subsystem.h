#include "type.h"
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>
#include <map>
#include <string>

class map_subsystem {
public:
    map_subsystem() = default;
    ~map_subsystem() = default;
    map_subsystem(const map_subsystem &) = delete;
    map_subsystem(map_subsystem &&) = delete;
    map_subsystem &operator=(const map_subsystem &) = delete;
    map_subsystem &operator=(map_subsystem &&) = delete;

    void map_op_get();
    void map_op_set();

private:
};