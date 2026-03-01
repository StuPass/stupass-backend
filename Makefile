.PHONY: db-create db-gen-entities

db-create:
	sea-orm-cli migrate up

db-gen-entities:
	sea-orm-cli generate entity -u sqlite://data.db -o src/entities

db-seeder:
	cargo run -p seeder -- --num-users $(num_users) --db-url $(if $(db_url),$(db_url),sqlite://data.db?mode=rwc)