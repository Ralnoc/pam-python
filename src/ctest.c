/*
 * Best compiled & run using the Makefile target "test".  To compile and run
 * manually:
 *   gcc -O0 -g -Wall -o test -lpam test.c
 *   sudo ln -s $PWD/test-pam_python.pam /etc/pam.d
 *   ./ctest
 *   sudo rm /etc/pam.d/test-pam_python.pam
 */
#define	_GNU_SOURCE

#ifdef __APPLE__
#include <mach-o/dyld.h>
#else
#include <link.h>
#endif
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct walk_info {
  int		libpam_python_seen;
  int		python_seen;
};

static int conv(
    int num_msg, const struct pam_message** msg, struct pam_response** resp, void *appdata_ptr)
{
  int		i;

  (void)appdata_ptr;
  *resp = malloc(num_msg * sizeof(**resp));
  for (i = 0; i < num_msg; i += 1)
  {
    (*resp)[i].resp = strdup((*msg)[i].msg);
    (*resp)[i].resp_retcode = (*msg)[i].msg_style;
  }
  return 0;
}

static void call_pam(
    int* exit_status, const char* who, pam_handle_t* pamh,
    int (*func)(pam_handle_t*, int))
{
  int pam_result = (*func)(pamh, 0);

  if (pam_result == PAM_SUCCESS)
    return;
  fprintf(
    stderr, "%s failed: %d %s\n",
    who, pam_result, pam_strerror(pamh, pam_result));
  *exit_status = 1;
}

#ifdef __APPLE__
static void walk_dlls(struct walk_info* walk_info)
{
  int image_index;
  walk_info->libpam_python_seen = 0;
  walk_info->python_seen = 0;
  for (image_index = 0; image_index < _dyld_image_count(); image_index += 1) {
    const char* image_name = _dyld_get_image_name(image_index);
    if (strstr(image_name, "/pam_python.so") != 0)
      walk_info->libpam_python_seen = 1;
    if (strstr(image_name, "/libpython") != 0)
      walk_info->python_seen = 1;
  }
}
#else
static int dl_walk(struct dl_phdr_info* info, size_t size, void* data)
{
  struct walk_info*		walk_info = data;

  (void)size;
  if (strstr(info->dlpi_name, "/pam_python.so") != 0)
    walk_info->libpam_python_seen = 1;
  if (strstr(info->dlpi_name, "/libpython") != 0)
    walk_info->python_seen = 1;
  return 0;
}

static void walk_dlls(struct walk_info* walk_info)
{
  walk_info->libpam_python_seen = 0;
  walk_info->python_seen = 0;
  dl_iterate_phdr(dl_walk, walk_info);
}
#endif

int main(int argc, char **argv)
{
  int			exit_status;
  struct pam_conv	convstruct;
  pam_handle_t*		pamh;
  struct walk_info	walk_info_before;
  struct walk_info	walk_info_after;

  (void)argc;
  (void)argv;
  if (access("/etc/pam.d/test-pam_python.pam", 0) != 0)
  {
    fprintf(
      stderr,
      "**WARNING**\n"
      "  This test requires ./test-pam_python.pam configuration to be\n"
      "  available to PAM But it doesn't appear to be in /etc/pam.d.\n"
    );
  }
  printf("Testing calls from C");
  fflush(stdout);
  convstruct.conv = conv;
  convstruct.appdata_ptr = 0;
  if (pam_start("test-pam_python.pam", "", &convstruct, &pamh) == -1)
  {
    fprintf(stderr, "pam_start failed\n");
    exit(1);
  }
  exit_status = 0;
  call_pam(&exit_status, "pam_authenticate", pamh, pam_authenticate);
  call_pam(&exit_status, "pam_chauthtok", pamh, pam_chauthtok);
  call_pam(&exit_status, "pam_acct_mgmt", pamh, pam_acct_mgmt);
  call_pam(&exit_status, "pam_open_session", pamh, pam_open_session);
  call_pam(&exit_status, "pam_close_session", pamh, pam_close_session);
  walk_dlls(&walk_info_before);
  call_pam(&exit_status, "pam_end", pamh, pam_end);
  if (exit_status == 0)
    printf(" OK\n");
  walk_dlls(&walk_info_after);
  printf("Testing dll load/unload ");
  if (!walk_info_before.libpam_python_seen)
  {
    fprintf(stderr, "It looks like pam_python.so wasn't loaded!\n");
    exit_status = 1;
  }
  else if (!walk_info_before.python_seen)
  {
    fprintf(stderr, "It looks like libpythonX.Y.so wasn't loaded!\n");
    exit_status = 1;
  }
  else if (walk_info_after.libpam_python_seen)
  {
    fprintf(stderr, "pam_python.so wasn't unloaded.\n");
    exit_status = 1;
  }
  else if (walk_info_after.python_seen)
  {
    fprintf(stderr, "libpythonX.Y.so wasn't uloaded.\n");
    exit_status = 1;
  }
  else
    printf("OK\n");
  return exit_status;
}
