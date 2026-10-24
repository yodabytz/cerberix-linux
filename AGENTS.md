# Deployment and Release Requirements

- Never downgrade code, packages, plugins, or container application files.
- Do not install or update anything on the user's VM unless explicitly asked.
  The user upgrades that VM through pacman. Read-only diagnosis is allowed.
- Finish releases end to end: test the actual packaged host/plugin combination,
  commit and push the scoped changes, publish signed artifacts and metadata to
  the local and Cloudflare repositories, and verify the public downloads.
- Do not call a fix finished while it remains unpublished, unless the user has
  explicitly requested testing before publication. Report genuine blockers.
- Publish package files before repository metadata. Verify the repository URL
  configured on the user's machine actually advertises the corrected version.
- Before replacing a container, preserve and compare its running application
  code with the replacement image. In-app updates may exist only in its writable
  layer; a cached image tagged latest is not proof that it is current.
