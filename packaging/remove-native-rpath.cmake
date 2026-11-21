# Standalone plugin files are copied from the build tree. Do not ship build
# directories or empty search entries that could resolve libraries from cwd.
file(RPATH_REMOVE FILE "${CMAKE_ARGV3}")
