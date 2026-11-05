include "root" {
  path = find_in_parent_folders("root.hcl")
}

inputs = {
  bucket_name = "corp-public-assets"
  bucket_acl  = "public-read"
}
