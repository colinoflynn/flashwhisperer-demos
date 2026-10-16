/* httpd fs.c includes this when HTTPD_USE_CUSTOM_FSDATA is set. All content is
 * served from fs_open_custom() in https_server.c, so the static table is empty.
 */
#define FS_ROOT NULL
#define FS_NUMFILES 0
