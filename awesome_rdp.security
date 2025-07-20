package awesome_rdp.security

default allow = false

allow {
  input.method == "GET"
  input.path = "/health"
}

allow {
  input.user_role == "admin"
  input.action in {"connect", "transfer", "exec", "save", "load"}
}

allow {
  input.user_role == "user"
  input.action in {"connect", "transfer"}
}