#include "logger.h"

static FILE *fp = NULL;

void write_lg(const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(fp, format, args);
  va_end(args);
  fprintf(fp, "\n");
}

void init_logger(char *file_name) { fp = fopen(file_name, "w"); }

void destory_logger() { fclose(fp); }
