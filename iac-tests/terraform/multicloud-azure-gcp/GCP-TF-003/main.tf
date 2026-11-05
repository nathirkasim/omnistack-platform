provider "google" {
  project = "synth-eval-project"
  region  = "us-central1"
}

resource "google_storage_bucket" "hardened_bucket" {
  name                        = "synth-eval-hardened-bucket"
  location                    = "US"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_binding" "service_account_access" {
  bucket  = google_storage_bucket.hardened_bucket.name
  role    = "roles/storage.objectViewer"
  members = ["serviceAccount:app-worker@synth-eval-project.iam.gserviceaccount.com"]
}
