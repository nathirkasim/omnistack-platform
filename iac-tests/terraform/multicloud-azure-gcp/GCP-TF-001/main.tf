provider "google" {
  project = "synth-eval-project"
  region  = "us-central1"
}

resource "google_storage_bucket" "public_bucket" {
  name     = "synth-eval-open-bucket-2026"
  location = "US"
}

resource "google_storage_bucket_iam_binding" "public_rule" {
  bucket  = google_storage_bucket.public_bucket.name
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}
