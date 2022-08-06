After cloning the repo, build stuff

```sh
cargo build
```

Note: Please run all commands from the root directory of the project.

Help

```sh
cargo run -- -h
```

Login (check `db.json` for creds)

```sh
cargo run -- login --name <username> --password <password>
```

Access

```sh
cargo run -- access --token <token>
```
