# Creates random string used for identification purposes
resource "random_string" "random" {
  length  = 8
  special = false
  upper   = false
}