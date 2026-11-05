provider "google" {
  project = "synth-eval-project"
  region  = "us-central1"
}

resource "google_compute_firewall" "open_all" {
  name    = "allow-all-ingress"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["0.0.0.0/0"]
}
